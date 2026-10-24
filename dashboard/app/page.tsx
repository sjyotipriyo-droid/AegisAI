"use client";
import { useState } from "react";
import { Shield, Lock, Unlock, Globe, KeyRound, AlertTriangle, CheckCircle2, FileCode, Download } from "lucide-react";

interface Telemetry {
  target: string;
  domain: string;
  auth_status: string;
  authorized: boolean;
  tls_posture: {
    https_supported?: boolean;
    tls_version?: string;
    cipher_suite?: string;
    issuer?: string;
    status?: string;
  };
  dns_posture: {
    spf_present: boolean;
    dmarc_present: boolean;
    issues: string[];
  };
  missing_headers: { header: string; impact: string }[];
  information_leakage: string[];
  cors_issue: string | null;
  endpoint_exposure: string[];
}

export default function AegisDashboard() {
  const [targetUrl, setTargetUrl] = useState("example.com");
  const [scanMode, setScanMode] = useState<"public" | "deep">("public");
  const [masterKey, setMasterKey] = useState("");
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const runAudit = async () => {
    setErrorMsg(null);
    setLoading(true);
    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl, scanMode, masterKey }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setErrorMsg(data.error || "Audit failed");
      } else {
        setTelemetry(data.telemetry);
        setAiReport(data.aiReport);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network error";
      setErrorMsg(`Connection failed: ${msg}`);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = () => {
    if (!aiReport) return;
    const blob = new Blob([aiReport], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `AegisAI_Audit_${telemetry?.domain || "report"}.md`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6 font-sans">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-zinc-800 pb-5 gap-4">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-emerald-400" />
            <div>
              <h1 className="text-2xl font-bold tracking-wider bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
                AEGIS-AI // WEB SECURITY & POSTURE AUDITOR
              </h1>
              <p className="text-xs text-zinc-400">
                Ethical Open-Core Architecture • Anti-Abuse Ownership & Master Key Gate
              </p>
            </div>
          </div>
          <span className="text-xs font-mono bg-zinc-900 border border-zinc-800 px-3 py-1.5 rounded-full text-emerald-400">
            v2.0 Enterprise Open-Core
          </span>
        </header>

        {/* Control Panel */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 space-y-1.5">
              <label className="text-xs font-mono uppercase text-zinc-400 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-emerald-400" /> Target Website Domain / URL
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2.5 text-sm font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-mono uppercase text-zinc-400">Security Scan Tier</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setScanMode("public")}
                  className={`py-2.5 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 border ${
                    scanMode === "public"
                      ? "bg-emerald-500/20 border-emerald-500 text-emerald-300"
                      : "bg-zinc-950 border-zinc-800 text-zinc-400"
                  }`}
                >
                  <Unlock className="w-3.5 h-3.5" /> Public Passive
                </button>
                <button
                  onClick={() => setScanMode("deep")}
                  className={`py-2.5 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 border ${
                    scanMode === "deep"
                      ? "bg-amber-500/20 border-amber-500 text-amber-300"
                      : "bg-zinc-950 border-zinc-800 text-zinc-400"
                  }`}
                >
                  <Lock className="w-3.5 h-3.5" /> Deep + AI Audit
                </button>
              </div>
            </div>
          </div>

          {/* Authorization Gate Input */}
          {scanMode === "deep" && (
            <div className="bg-amber-950/20 border border-amber-500/30 rounded-lg p-3.5 flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="text-xs text-amber-200/90 space-y-1">
                <p className="font-semibold flex items-center gap-1.5">
                  <KeyRound className="w-4 h-4 text-amber-400" /> Ethical Anti-Abuse Authorization Required
                </p>
                <p className="text-zinc-400">
                  Enter your Admin Master Key, OR leave blank if you placed{" "}
                  <code className="text-amber-300">aegis-verify-{targetUrl.replace(/^https?:\/\//, "")}</code> in DNS TXT.
                </p>
              </div>
              <input
                type="password"
                value={masterKey}
                onChange={(e) => setMasterKey(e.target.value)}
                placeholder="Enter AEGIS_MASTER_KEY..."
                className="w-full md:w-72 bg-zinc-950 border border-amber-500/40 rounded-lg px-3 py-2 text-xs font-mono text-amber-300 focus:outline-none"
              />
            </div>
          )}

          <button
            onClick={runAudit}
            disabled={loading}
            className="w-full bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold py-2.5 rounded-lg text-sm transition disabled:opacity-50"
          >
            {loading
              ? scanMode === "deep"
                ? "Verifying Authorization & Running Deep AI Architecture Audit (~10s)..."
                : "Running Passive Telemetry Scan..."
              : scanMode === "deep"
              ? "🔒 Execute Authorized Deep Audit & Generate Unfiltered AI Hardening Patches"
              : "Execute Safe Public Posture Scan"}
          </button>
        </div>

        {/* Error Banner */}
        {errorMsg && (
          <div className="bg-red-950/60 border border-red-500/50 text-red-200 p-4 rounded-xl text-xs font-mono">
            [!] {errorMsg}
          </div>
        )}

        {/* Telemetry Results */}
        {telemetry && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-2">
              <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" /> Cryptographic TLS & DNS Identity
              </h3>
              <div className="text-xs font-mono space-y-1.5 text-zinc-300">
                <p>
                  <span className="text-zinc-500">Domain:</span> {telemetry.domain} ({telemetry.auth_status})
                </p>
                <p>
                  <span className="text-zinc-500">TLS Protocol:</span> {telemetry.tls_posture.tls_version} (
                  {telemetry.tls_posture.status})
                </p>
                <p>
                  <span className="text-zinc-500">Cipher Suite:</span> {telemetry.tls_posture.cipher_suite}
                </p>
                <p>
                  <span className="text-zinc-500">Email Security:</span> SPF:{" "}
                  {telemetry.dns_posture.spf_present ? "✅" : "❌"} | DMARC:{" "}
                  {telemetry.dns_posture.dmarc_present ? "✅" : "❌"}
                </p>
                {telemetry.information_leakage.length > 0 && (
                  <p className="text-amber-400">
                    <span className="text-zinc-500">Server Leaks:</span> {telemetry.information_leakage.join(", ")}
                  </p>
                )}
              </div>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-2">
              <h3 className="text-sm font-bold text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Missing Defense-in-Depth Headers (
                {telemetry.missing_headers.length})
              </h3>
              <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                {telemetry.missing_headers.map((h, i) => (
                  <div key={i} className="text-xs bg-zinc-950 p-2 rounded border border-zinc-800">
                    <span className="font-mono font-bold text-red-300">{h.header}</span>
                    <p className="text-zinc-400 text-[11px]">{h.impact}</p>
                  </div>
                ))}
                {telemetry.missing_headers.length === 0 && (
                  <p className="text-xs text-emerald-400">All core security headers are enforced!</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* AI Hardcore Report */}
        {aiReport && (
          <div className="bg-zinc-900 border border-amber-500/40 rounded-xl p-5 space-y-4">
            <div className="flex justify-between items-center border-b border-zinc-800 pb-3">
              <h2 className="text-base font-bold text-amber-400 flex items-center gap-2">
                <FileCode className="w-5 h-5" /> Unfiltered Principal Security Architect Report & Hardening Patches
              </h2>
              <button
                onClick={downloadReport}
                className="bg-zinc-800 hover:bg-zinc-700 text-zinc-200 px-3 py-1.5 rounded-lg text-xs flex items-center gap-2"
              >
                <Download className="w-4 h-4 text-amber-400" /> Download .MD Report
              </button>
            </div>
            <pre className="whitespace-pre-wrap font-mono text-xs text-zinc-200 bg-zinc-950 p-4 rounded-lg border border-zinc-800 max-h-[600px] overflow-y-auto leading-relaxed">
              {aiReport}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}