import { NextResponse } from "next/server";
import { GoogleGenAI } from "@google/genai";
import dns from "node:dns/promises";
import tls from "node:tls";

interface MissingHeader {
  header: string;
  impact: string;
}

function cleanDomain(inputUrl: string): string {
  let formatted = inputUrl.trim();
  if (!formatted.startsWith("http://") && !formatted.startsWith("https://")) {
    formatted = "https://" + formatted;
  }
  try {
    const parsed = new URL(formatted);
    return parsed.hostname;
  } catch {
    return formatted;
  }
}

async function checkTlsSecurity(domain: string) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: domain, port: 443, servername: domain, timeout: 4000 },
      () => {
        const protocol = socket.getProtocol() || "Unknown";
        const cipher = socket.getCipher();
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve({
          https_supported: true,
          tls_version: protocol,
          cipher_suite: cipher ? cipher.name : "Unknown",
          issuer: cert?.issuer?.O || "Unknown",
          expires: cert?.valid_to || "Unknown",
          status: protocol === "TLSv1.3" || protocol === "TLSv1.2" ? "SECURE" : "WEAK_TLS",
        });
      }
    );
    socket.on("error", (err) => {
      resolve({ https_supported: false, status: "SSL_ERROR", error: err.message });
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ https_supported: false, status: "TIMEOUT" });
    });
  });
}

async function checkDnsPosture(domain: string) {
  let spfPresent = false;
  let dmarcPresent = false;
  const issues: string[] = [];

  try {
    const txtRecords = await dns.resolveTxt(domain);
    for (const record of txtRecords) {
      if (record.join("").includes("v=spf1")) spfPresent = true;
    }
  } catch {
    // No TXT records
  }

  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    for (const record of dmarcRecords) {
      if (record.join("").includes("v=DMARC1")) dmarcPresent = true;
    }
  } catch {
    // No DMARC records
  }

  if (!spfPresent) issues.push("Missing SPF record (Email spoofing risk)");
  if (!dmarcPresent) issues.push("Missing DMARC record (No anti-phishing policy)");

  return { spf_present: spfPresent, dmarc_present: dmarcPresent, issues };
}

async function verifyOwnership(domain: string, token: string): Promise<boolean> {
  try {
    const res = await fetch(`https://${domain}/.well-known/aegis-verify.txt`);
    if (res.ok) {
      const text = await res.text();
      if (text.includes(token)) return true;
    }
  } catch {
    // Ignore fetch error
  }

  try {
    const txtRecords = await dns.resolveTxt(domain);
    for (const rec of txtRecords) {
      if (rec.join("").includes(token)) return true;
    }
  } catch {
    // Ignore DNS error
  }
  return false;
}

export async function POST(req: Request) {
  try {
    const { targetUrl, scanMode, masterKey } = await req.json();
    if (!targetUrl) {
      return NextResponse.json({ error: "Target URL is required" }, { status: 400 });
    }

    const domain = cleanDomain(targetUrl);
    const fullUrl = targetUrl.startsWith("http") ? targetUrl : `https://${domain}`;

    // Verify Authorization Gate for Mode 2 (Deep Audit + AI Remediation)
    let isAuthorized = false;
    let authMessage = "Public Passive Scan Mode (Safe Open-Source Tier)";

    if (scanMode === "deep") {
      const serverMasterKey = process.env.AEGIS_MASTER_KEY;
      if (serverMasterKey && masterKey === serverMasterKey) {
        isAuthorized = true;
        authMessage = "Authorized via Master Admin Key";
      } else {
        const expectedToken = `aegis-verify-${domain}`;
        const domainVerified = await verifyOwnership(domain, expectedToken);
        if (domainVerified) {
          isAuthorized = true;
          authMessage = "Authorized via Domain Ownership Verification";
        } else {
          return NextResponse.json(
            {
              error: `Authorization Denied! To prevent unethical scanning of ${domain}, Deep Audit & AI Remediation require either a valid AEGIS_MASTER_KEY or placing token '${expectedToken}' in DNS TXT / /.well-known/aegis-verify.txt.`,
            },
            { status: 403 }
          );
        }
      }
    }

    const [tlsPosture, dnsPosture] = await Promise.all([
      checkTlsSecurity(domain),
      checkDnsPosture(domain),
    ]);

    const missingHeaders: MissingHeader[] = [];
    const infoLeakage: string[] = [];
    const endpointExposure: string[] = [];
    let corsIssue: string | null = null;

    try {
      const res = await fetch(fullUrl, {
        method: "GET",
        headers: { "User-Agent": "AegisAI-Security-Auditor/2.0" },
      });

      const requiredHeaders: Record<string, string> = {
        "content-security-policy": "HIGH - Mitigates XSS & Data Injection",
        "strict-transport-security": "HIGH - Enforces HTTPS & prevents SSL Stripping",
        "x-frame-options": "MEDIUM - Prevents Clickjacking attacks",
        "x-content-type-options": "LOW - Prevents MIME-sniffing (nosniff)",
        "referrer-policy": "LOW - Controls URL token leakage in Referer header",
        "permissions-policy": "LOW - Restricts Camera, Mic, Geolocation APIs",
      };

      for (const [h, impact] of Object.entries(requiredHeaders)) {
        if (!res.headers.get(h)) {
          missingHeaders.push({ header: h, impact });
        }
      }

      for (const leak of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
        const val = res.headers.get(leak);
        if (val) infoLeakage.push(`${leak}: ${val}`);
      }

      if (res.headers.get("access-control-allow-origin") === "*") {
        corsIssue = "Wildcard CORS ('*') detected";
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "HTTP connection failed";
      infoLeakage.push(`HTTP Fetch Error: ${msg}`);
    }

    if (isAuthorized) {
      for (const path of ["/.well-known/security.txt", "/robots.txt"]) {
        try {
          const pRes = await fetch(`https://${domain}${path}`);
          if (pRes.ok) endpointExposure.push(`${path} (HTTP 200)`);
        } catch {
          // Ignore
        }
      }
    }

    const telemetry = {
      target: fullUrl,
      domain,
      auth_status: authMessage,
      authorized: isAuthorized,
      tls_posture: tlsPosture,
      dns_posture: dnsPosture,
      missing_headers: missingHeaders,
      information_leakage: infoLeakage,
      cors_issue: corsIssue,
      endpoint_exposure: endpointExposure,
    };

    let aiReport: string | null = null;
    if (isAuthorized) {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return NextResponse.json({ error: "GEMINI_API_KEY missing in .env.local" }, { status: 500 });
      }
      const ai = new GoogleGenAI({ apiKey });
      const systemPrompt = `You are AegisAI, a blunt, no-nonsense Principal Application Security Architect. Speak with direct, unfiltered technical candor about every security weakness found in the telemetry. Structure your Markdown report strictly into:
1. BRUTAL POSTURE SUMMARY & RISK SCORE (Score out of 100 + immediate real-world attack surface).
2. TECHNICAL VULNERABILITY BREAKDOWN (Defensive analysis of each missing header, TLS flaw, or DNS gap).
3. PRODUCTION-READY HARDENING PATCHES (Exact copy-paste config blocks for Next.js next.config.mjs, Vercel vercel.json, Nginx nginx.conf, and DNS SPF/DMARC records).`;

      const response = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: `${systemPrompt}\n\nTelemetry:\n${JSON.stringify(telemetry, null, 2)}`,
      });
      aiReport = response.text || null;
    }

    return NextResponse.json({ telemetry, aiReport });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}