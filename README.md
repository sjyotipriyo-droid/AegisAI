# ??? AegisAI — Ethical Web Security & Posture Auditor (Open-Core)

**AegisAI** is a dual-engine (Python CLI + Next.js 16 Full-Stack Dashboard) Web Security Posture & Compliance Auditor designed for DevSecOps teams and security engineers.

## ?? Ethical Open-Core & Anti-Abuse Architecture
To prevent unauthorized or malicious active scanning against third-party infrastructure, AegisAI enforces a strict **Dual-Verification Gate**:
1. **Public Passive Tier (Open-Source Safe):** Performs non-intrusive cryptographic TLS/SSL handshake inspection, DNS email security validation (SPF/DMARC), and passive HTTP security header analysis.
2. **?? Authorized Deep-Audit Tier (Gated):** Deep cookie flag inspection, endpoint governance auditing, and the **Unfiltered Principal AI Security Architect (Auto-Patch Generator)** are strictly locked behind:
   - **Domain Ownership Verification:** Placing a cryptographic token in the target's DNS TXT record or /.well-known/aegis-verify.txt.
   - **Master Admin Authorization Key:** Controlled exclusively by the repository administrator (AEGIS_MASTER_KEY).

## ?? Tech Stack
- **Core CLI Engine:** Python 3.12, httpx, dnspython, ssl, ich, Google GenAI SDK (gemini-3.8-flash)
- **Web Dashboard:** Next.js 16 (App Router), TypeScript, Tailwind CSS, Node.js 	ls & dns native modules
