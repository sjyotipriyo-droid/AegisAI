<div align="center">

# 🛡️ AegisAI — Ethical Open-Core Web Security Posture & Compliance Auditor

**Audit a website's security posture in seconds, then get the exact fixes, without handing attackers a scanner.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://aegis-ai-iota-seven.vercel.app/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Next.js 16](https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-AI-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)](https://ai.google.dev/)
[![License: Open-Core](https://img.shields.io/badge/License-Open--Core-2EA44F?style=for-the-badge)](#-license)

[Live Demo](https://aegis-ai-iota-seven.vercel.app/) · [Architecture](#%EF%B8%8F-the-ethical-open-core--anti-abuse-architecture) · [What It Inspects](#-deep-dive-what-telemetry-does-aegisai-inspect) · [Install](#-step-by-step-local-installation--usage) · [Disclaimer](#%EF%B8%8F-ethical-disclosure--legal-disclaimer)

</div>

---

## 🌟 What is AegisAI?

### The plain-English version

Every website is like a building with many doors and windows. Some are locked, some are closed but not locked, and some are wide open. The problem is that the owner usually can't see which is which. Most of these gaps are not exotic bugs. They are missing settings:

- The connection to the site isn't properly encrypted or uses outdated encryption.
- Anyone can send emails that look like they come from the company's domain.
- The browser is never told to block common attacks like clickjacking or script injection.
- The server announces exactly which software and version it runs, which helps attackers choose their tools.

**AegisAI checks all of that for you** and tells you in plain language what is open, how an attacker would use it, and what to change to close it.

### Why another scanner?

Security scanners usually fail in one of two ways:

| The problem | The result |
|---|---|
| Open tools that stay shallow to avoid misuse | Too weak to be useful |
| Powerful tools with no guardrails | Easy to point at websites the user doesn't own |

AegisAI takes a different route. Anyone can run safe, **passive** checks on any domain. The **deep audit and AI remediation** unlock only when you prove you own the domain (or you are the operator of the instance). That is the **Open-Core + Anti-Abuse Gate**.

> ### ⚡ Try It Live in 10 Seconds
> 1. Open **https://aegis-ai-iota-seven.vercel.app/**
> 2. Type a domain, for example `example.com`
> 3. Read your results: TLS, email security, security headers, CORS, and tech-stack leakage

---

## ⚖️ The Ethical Open-Core & Anti-Abuse Architecture

AegisAI uses a **Dual-Verification Open-Core** design. The scanning engine is open source. What the tool is allowed to do against a given target depends on who is asking and whether they can prove authority over that domain.

### Request flow

```text
                        +---------------------------+
                        |   User submits a domain   |
                        +-------------+-------------+
                                      |
                                      v
                +---------------------------------------------+
                |  TIER 1 - Public Passive Scan (open to all) |
                |  TLS / cipher / cert  |  SPF + DMARC        |
                |  HTTP security headers|  CORS wildcards     |
                |  Server / X-Powered-By leakage              |
                +----------------------+----------------------+
                                       |
                       wants deep audit + AI remediation?
                                       |
                                       v
                          +---------------------------+
                          |    AUTHORIZATION GATE     |
                          |   (dual verification)     |
                          +------+-------------+------+
                                 |             |
               +-----------------+             +------------------+
               |                                                  |
               v                                                  v
  +-----------------------------+                 +----------------------------+
  | Path A: Domain ownership    |                 | Path B: Admin master key   |
  |  - DNS TXT token, OR        |                 |  - AEGIS_MASTER_KEY        |
  |  - /.well-known/            |                 |    (instance operator)     |
  |    aegis-verify.txt         |                 +--------------+-------------+
  +--------------+--------------+                                |
                 |                                               |
                 +-----------------------+-----------------------+
                                         |
                                    verified?
                                    /       \
                                  no         yes
                                  |           |
                                  v           v
                       Tier 2 stays      +----------------------------------------+
                       LOCKED            | TIER 2 - Authorized Deep Audit         |
                                         |  Cookie flags | security.txt | robots  |
                                         |  + AI Principal Security Architect     |
                                         |  -> score /100 + exploits + patches    |
                                         +----------------------------------------+
```

### Tier 1 vs Tier 2

| | **Tier 1: Public Passive Scan** | **Tier 2: 🔒 Authorized Deep Audit + AI Architect** |
|---|---|---|
| **Who can run it** | Anyone, any domain | Verified domain owners or the instance operator |
| **What it does** | Reads only what any browser or DNS resolver can already see | Everything in Tier 1, plus cookie inspection, governance endpoint checks, and AI analysis |
| **Checks** | TLS/SSL handshake and cipher suite, certificate issuer and expiry, SPF, DMARC, 6 HTTP security headers, CORS wildcards, `Server` / `X-Powered-By` leakage | `HttpOnly` / `Secure` cookie flags, `/.well-known/security.txt`, `/robots.txt`, AI Security Architect report |
| **AI remediation** | ❌ | ✅ Posture score, exploitation mechanics, drop-in patches |
| **Safety profile** | Non-intrusive, no payloads, no fuzzing, no authentication attempts | Gated behind proof of authority |
| **Authorization required** | None | **One of:** `/.well-known/aegis-verify.txt` token, DNS TXT token `aegis-verify-<domain>`, or `AEGIS_MASTER_KEY` |

<details>
<summary><b>How domain ownership verification works</b></summary>

<br>

You prove control of a domain by publishing a token that only the owner could place. Use either method:

**Option 1: Well-known file**

Serve the verification token at:

```text
https://<your-domain>/.well-known/aegis-verify.txt
```

**Option 2: DNS TXT record**

Add a TXT record containing the token:

```text
aegis-verify-<your-domain>
```

If either is present, Tier 2 unlocks for that domain. If neither is present and no valid master key is supplied, the deep audit and AI engine stay locked.

</details>

---

## 🔍 Deep-Dive: What Telemetry Does AegisAI Inspect?

Each check below includes a beginner explanation and the technical mechanics.

### 1. Cryptographic TLS/SSL Handshake & Cipher Suite Inspection

- **What it is (for beginners):** The padlock in your browser. TLS encrypts traffic between you and a website so nobody in the middle can read or change it. AegisAI checks which TLS version the site uses, how strong its encryption is, who issued its certificate, and when that certificate expires.
- **How attackers abuse it / technical mechanics:** AegisAI inspects the negotiated protocol (TLS 1.2 or 1.3) and cipher suite (for example `TLS_AES_256_GCM_SHA384`). Legacy protocol versions and weak cipher suites open the door to downgrade and decryption attacks. An expired or untrusted certificate breaks the trust chain and trains users to click through browser warnings, which is exactly what a man-in-the-middle attacker needs.

### 2. DNS Identity & Email Anti-Spoofing (`SPF` & `DMARC`)

- **What it is (for beginners):** Email has no built-in "From" verification, so anyone can send mail that claims to come from your domain. SPF lists which servers may send mail for you. DMARC tells receiving servers what to do when a message fails the check.
- **How attackers abuse it / technical mechanics:** A missing SPF record, a soft-fail `~all`, or a DMARC policy of `p=none` means spoofed mail is still delivered. Attackers use this for phishing and business email compromise, sending messages that appear to come from your own domain. AegisAI validates both records and recommends enforcement (`-all` and `p=reject`).

### 3. Defense-in-Depth HTTP Security Headers

- **What it is (for beginners):** Short instructions your website sends to the browser: "block this kind of attack, don't allow that behavior." Without them, the browser falls back to permissive defaults.
- **How attackers abuse it / technical mechanics:**

| Header | Missing it enables |
|---|---|
| `Content-Security-Policy` | Script injection and **DOM XSS** with data exfiltration to attacker-controlled origins |
| `Strict-Transport-Security` | **SSL stripping** (for example with `mitmproxy`) that silently downgrades HTTPS to HTTP |
| `X-Frame-Options` | **Clickjacking / UI redressing**: your page loaded invisibly inside an attacker's frame |
| `X-Content-Type-Options` | **MIME sniffing**: the browser executes a file as a script even though it was served as something else |
| `Referrer-Policy` | Leaking full URLs (paths, tokens, IDs) to third parties through the `Referer` header |
| `Permissions-Policy` | Unrestricted access to powerful browser features (camera, microphone, geolocation) by embedded or injected content |

### 4. Server Tech-Stack Fingerprinting & CORS Wildcards

- **What it is (for beginners):** Servers often announce their software and version, like a house with a sign saying which lock brand it uses. CORS settings decide which other websites are allowed to read your site's data from a browser.
- **How attackers abuse it / technical mechanics:** `Server` and `X-Powered-By` headers let attackers match the exact stack to known CVEs and skip blind probing. A wildcard `Access-Control-Allow-Origin: *` lets any origin read responses from that endpoint in a browser, which becomes a real problem when the endpoint exposes data that should not be public. AegisAI flags both so you can strip the banners and tighten the origin allowlist.

### 5. Cookie Security Flags & Governance Endpoints 🔒 *(Tier 2)*

- **What it is (for beginners):** Cookies often hold your login session. Flags control who can read them. Governance files like `security.txt` tell researchers how to report a vulnerability responsibly.
- **How attackers abuse it / technical mechanics:** A session cookie without `HttpOnly` can be read by injected JavaScript, so a single XSS bug becomes full session theft. Without `Secure`, the cookie can travel over plain HTTP and be intercepted. A missing `/.well-known/security.txt` means researchers have no sanctioned disclosure channel, and `/robots.txt` can unintentionally advertise sensitive paths. AegisAI inspects all of these on verified domains only.

---

## 🧠 Unfiltered AI Principal Security Architect & Auto-Patch Engine

Tier 2 hands your verified audit data to **Google Gemini**, prompted to act as a blunt **Principal Application Security Architect and Red-Team Auditor**.

> **"Unfiltered" means no filler, not no ethics.** The AI skips generic reassurance and disclaimers and tells you what is broken and why it matters. It only runs after the authorization gate has been passed.

**What it produces:**

1. **A 0-100 Posture Score**, broken down across four areas:

   | Category | Covers |
   |---|---|
   | **TLS Cryptography** | Protocol version, cipher suite, certificate health |
   | **Transport Integrity** | HSTS and protections against downgrade and stripping |
   | **Browser Sandboxing** | CSP, framing, MIME sniffing, referrer and permissions controls |
   | **DNS Identity** | SPF and DMARC enforcement |

2. **Real exploitation mechanics** for every missing control, such as how SSL stripping works with `mitmproxy`, how DOM XSS exfiltrates data, and how clickjacking tricks a user into clicking.
3. **Copy-pasteable, production-ready hardening patches:**

   | Target | Output |
   |---|---|
   | **Next.js** | `next.config.mjs` |
   | **Vercel** | `vercel.json` |
   | **Nginx** | `nginx.conf` |
   | **DNS** | Authoritative SPF and DMARC rejection records |

<details>
<summary><b>Example of the style of patch it generates</b></summary>

<br>

**`next.config.mjs`**

```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'; base-uri 'self'" },
        ],
      },
    ];
  },
};

export default nextConfig;
```

**DNS (SPF + DMARC enforcement)**

```text
example.com.         TXT  "v=spf1 include:_spf.google.com -all"
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
```

</details>

---

## 🛠️ Dual-Engine Tech Stack

AegisAI ships two engines that implement the same audit logic, so you can use whichever fits your workflow.

| | **Engine 1: Python CLI** | **Engine 2: Next.js Web Dashboard** |
|---|---|---|
| **Entry point** | `aegis.py` and `auditor.py` | `dashboard/` |
| **Runtime** | Python 3.12 | Next.js 16 (App Router), TypeScript, Node.js |
| **Network / crypto** | `ssl`, `socket`, `httpx` | Node.js native `node:tls` |
| **DNS** | `dnspython` | Node.js native `node:dns/promises` |
| **UI** | `rich` terminal tables and panels | Tailwind CSS, Lucide Icons |
| **AI** | `google-genai` | Google Gemini via serverless API routes |
| **Deployment** | Run locally | Vercel (live) |

```text
AegisAI/
├── aegis.py          # Python CLI engine
├── auditor.py        # Python audit logic
├── .env.example      # Environment variable reference
└── dashboard/        # Next.js 16 web dashboard (serverless API routes)
```

---

## 🚀 Step-by-Step Local Installation & Usage

### Prerequisites

- [Git](https://git-scm.com/)
- [Python 3.12](https://www.python.org/downloads/) (for the CLI)
- [Node.js](https://nodejs.org/) and npm (for the dashboard)
- A [Google Gemini API key](https://aistudio.google.com/) (only needed for Tier 2 AI remediation)

### Step 1: Clone the repository

```bash
git clone https://github.com/sjyotipriyo-droid/AegisAI.git
cd AegisAI
```

### Step 2: Run the Python CLI

```bash
# Install dependencies
pip install httpx dnspython rich google-genai

# Create your environment file from the template
cp .env.example .env          # macOS / Linux
copy .env.example .env        # Windows

# Edit .env and add your values (see below), then run:
py aegis.py                   # Windows
python3 aegis.py              # macOS / Linux
```

Enter a target domain when prompted.

### Step 3: Run the Next.js Web Dashboard

```bash
cd dashboard
npm install
```

Create `dashboard/.env.local`:

```env
GEMINI_API_KEY=your_gemini_api_key
AEGIS_MASTER_KEY=choose_a_long_random_secret
```

Start the dev server:

```bash
npm run dev
```

Open **http://localhost:3000**.

### Using the tiers

| You are... | What to do |
|---|---|
| **A public user** | Nothing. Tier 1 works out of the box on the [live app](https://aegis-ai-iota-seven.vercel.app/) or locally, with no key and no verification. |
| **A domain owner** | Prove ownership with a DNS TXT token or `/.well-known/aegis-verify.txt` to unlock the Tier 2 deep audit and AI remediation for your domain. |
| **Running your own instance** | Set `AEGIS_MASTER_KEY` in your `.env` or `dashboard/.env.local` and `GEMINI_API_KEY` for the AI engine. Keep both secret and never commit them. |

> 🔐 **Never commit `.env` or `.env.local`.** Both should be listed in `.gitignore`.

---

## 📄 Sample Audit Output Preview

> The output below is illustrative. Exact values depend on the target.

<details open>
<summary><b>Terminal audit table (Tier 1)</b></summary>

```text
 AegisAI | Target: example.com | Mode: Tier 1 (Public Passive Scan)

 +---------------------------+-------------------------------------+--------+
 | Check                     | Finding                             | Status |
 +---------------------------+-------------------------------------+--------+
 | TLS Protocol              | TLS 1.3                             | PASS   |
 | Cipher Suite              | TLS_AES_256_GCM_SHA384              | PASS   |
 | Certificate               | Issuer: Let's Encrypt, expires 54d  | PASS   |
 | SPF                       | v=spf1 ... ~all (soft fail)         | WARN   |
 | DMARC                     | p=none (monitoring only)            | WARN   |
 | Strict-Transport-Security | Missing                             | FAIL   |
 | Content-Security-Policy   | Missing                             | FAIL   |
 | X-Frame-Options           | DENY                                | PASS   |
 | X-Content-Type-Options    | Missing                             | FAIL   |
 | Referrer-Policy           | Missing                             | WARN   |
 | Permissions-Policy        | Missing                             | WARN   |
 | CORS                      | Access-Control-Allow-Origin: *      | WARN   |
 | Server Banner             | nginx/1.18.0 (version exposed)      | WARN   |
 +---------------------------+-------------------------------------+--------+
```

</details>

<details open>
<summary><b>Posture Score breakdown (Tier 2)</b></summary>

```text
 POSTURE SCORE:  58 / 100

 TLS Cryptography    24 / 25   [####################....]
 Transport Integrity 12 / 25   [##########..............]
 Browser Sandboxing  10 / 25   [########................]
 DNS Identity        12 / 25   [##########..............]

 TOP FINDING
 Missing Strict-Transport-Security
 -> An attacker on the same network can strip HTTPS with mitmproxy and
    read or modify traffic before the browser ever upgrades the connection.
 -> Fix: apply the generated next.config.mjs / vercel.json / nginx.conf patch.
```

</details>

---

## ⚠️ Ethical Disclosure & Legal Disclaimer

**AegisAI is built for defensive security, education, and authorized assessment.**

- **Only audit what you own or are authorized to test.** Tier 1 performs passive, non-intrusive checks, but you are still responsible for how and where you use any tool.
- **The authorization gate is a safeguard, not a license.** Verification proves control of a domain for Tier 2. It does not authorize you to test infrastructure you do not own.
- **No warranty.** AegisAI is provided "as is." Results are informational, may contain false positives or negatives, and are not a substitute for a professional security assessment.
- **Misuse is your responsibility.** The author and contributors accept no liability for damages or legal consequences arising from misuse of this software.
- **Found a vulnerability in AegisAI itself?** Please report it privately through the repository's GitHub security advisories rather than opening a public issue.

---

## 📜 License

AegisAI follows an **open-core** model: the core auditing engine is open source, and access to the deep-audit and AI remediation tier on the hosted service is gated by domain-ownership verification or an operator key. See the `LICENSE` file for the exact terms.

---

## 👤 Author

**Jyotipriyo Saha**
Cybersecurity builder focused on application security and ethical tool design.

[![GitHub](https://img.shields.io/badge/GitHub-@sjyotipriyo--droid-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sjyotipriyo-droid)

---

<div align="center">

**If AegisAI helped you find and fix a gap, consider giving the repo a ⭐**

[Try the Live App](https://aegis-ai-iota-seven.vercel.app/) · [View the Source](https://github.com/sjyotipriyo-droid/AegisAI)

</div>
