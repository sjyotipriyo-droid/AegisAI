import os
import json
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from google import genai
from google.genai import types
from auditor import run_security_audit, clean_domain, verify_domain_ownership

load_dotenv()
console = Console()

def generate_unfiltered_ai_audit(audit_data: dict) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "[!] Error: GEMINI_API_KEY not found in .env"

    client = genai.Client(api_key=api_key)

    system_instruction = """
    You are AegisAI, a blunt, no-nonsense Principal Application Security Architect and Red-Team Auditor.
    Do NOT use polite filler, corporate fluff, or generic disclaimers.
    Speak with direct, brutal technical candor about every security weakness found in the telemetry.

    Structure your Markdown report strictly into:
    1. BRUTAL POSTURE SUMMARY & RISK SCORE (Score out of 100 + immediate real-world attack surface).
    2. TECHNICAL VULNERABILITY BREAKDOWN (Explain exactly how an adversary abuses each missing header, TLS flaw, DNS gap, or cookie flag).
    3. PRODUCTION-READY HARDENING PATCHES (Provide exact copy-paste config blocks for Next.js `next.config.mjs`, Vercel `vercel.json`, Nginx `nginx.conf`, and DNS SPF/DMARC records).
    """

    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents=f"Analyze this web security telemetry and deliver a hardcore architectural audit:\n{json.dumps(audit_data, indent=2)}",
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.2,
        ),
    )
    return response.text

def main():
    console.print(Panel.fit(
        "[bold cyan]AEGIS-AI // ETHICAL WEB SECURITY & POSTURE AUDITOR[/bold cyan]\n"
        "[dim]Open-Core Architecture with Anti-Abuse Authorization Gate[/dim]",
        border_style="cyan"
    ))

    target = console.input("[bold yellow][?] Enter Target Website URL (e.g., example.com): [/bold yellow]").strip()
    if not target:
        return

    domain = clean_domain(target)
    console.print(f"\n[cyan][*] Target Domain Locked:[/cyan] [bold white]{domain}[/bold white]")
    console.print("[dim]Select Scan Mode:\n  [1] Public Passive Scan (Open-Source Safe Tier)\n  [2] Authorized Deep Audit + Unfiltered AI Remediation (Requires Master Key or DNS Proof)[/dim]")
    
    mode = console.input("[bold yellow][?] Choose Mode (1 or 2): [/bold yellow]").strip()
    authorized = False

    if mode == "2":
        auth_input = console.input("[bold red][🔒] Enter AEGIS_MASTER_KEY (or press Enter to verify via DNS/Well-Known token): [/bold red]").strip()
        master_key = os.getenv("AEGIS_MASTER_KEY")

        if master_key and auth_input == master_key:
            console.print("[bold green][✓] Master Admin Authorization Verified! Unlocking Deep Audit & AI Engine...[/bold green]")
            authorized = True
        else:
            token = f"aegis-verify-{domain}"
            console.print(f"[yellow][*] Checking domain ownership token '{token}' on {domain}...[/yellow]")
            if verify_domain_ownership(domain, token):
                console.print("[bold green][✓] Domain Ownership Verified! Unlocking Deep Audit...[/bold green]")
                authorized = True
            else:
                console.print("[bold red][✗] Authorization Denied! Falling back to Public Passive Scan to prevent unethical use.[/bold red]")

    console.print(f"\n[yellow][*] Running {('Authorized Deep' if authorized else 'Public Passive')} Security Scan on {domain}...[/yellow]")
    results = run_security_audit(target, authorized_deep_scan=authorized)

    # Display Summary Table
    table = Table(title=f"Security Telemetry: {domain}")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Findings", style="white")

    tls = results.get("tls_posture", {})
    table.add_row("SSL/TLS Posture", f"Status: {tls.get('status')} | Version: {tls.get('tls_version')} | Cipher: {tls.get('cipher_suite')}")
    
    dns_info = results.get("dns_posture", {})
    table.add_row("DNS Email Security", f"SPF: {dns_info.get('spf_present')} | DMARC: {dns_info.get('dmarc_present')}")
    
    missing_h = [h["header"] for h in results.get("missing_headers", [])]
    table.add_row("Missing Sec Headers", ", ".join(missing_h) if missing_h else "All Core Headers Present!")
    
    leaks = results.get("information_leakage", [])
    table.add_row("Tech Stack Leaks", ", ".join(leaks) if leaks else "None Detected")

    console.print(table)

    if authorized:
        console.print("\n[bold magenta][*] Engaging Unfiltered AegisAI Architect (Gemini 2.5 Flash)...[/bold magenta]")
        ai_report = generate_unfiltered_ai_audit(results)
        with open("aegis_audit_report.md", "w", encoding="utf-8") as f:
            f.write(ai_report)
        console.print("[bold green][SUCCESS] Full Hardcore Audit & Patch Report saved to 'aegis_audit_report.md'![/bold green]")
    else:
        console.print("\n[dim][!] AI Remediation & Deep Cookie/Endpoint Audit locked. Run with Mode [2] + Master Key to unlock.[/dim]")

if __name__ == "__main__":
    main()