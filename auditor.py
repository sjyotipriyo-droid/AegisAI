import ssl
import socket
import urllib.parse
import httpx
import dns.resolver

def clean_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path

def verify_domain_ownership(domain: str, expected_token: str) -> bool:
    """Checks DNS TXT record or /.well-known/aegis-verify.txt for ethical ownership proof."""
    # 1. Check HTTP Well-Known File
    try:
        res = httpx.get(f"https://{domain}/.well-known/aegis-verify.txt", timeout=4.0)
        if res.status_code == 200 and expected_token in res.text:
            return True
    except Exception:
        pass

    # 2. Check DNS TXT Record
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            if expected_token in rdata.to_text():
                return True
    except Exception:
        pass

    return False

def check_tls_security(domain: str) -> dict:
    """Inspects live SSL/TLS handshake, protocol version, and cipher strength."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "https_Supported": True,
                    "tls_version": version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Unknown"),
                    "expires": cert.get("notAfter", "Unknown"),
                    "status": "SECURE" if version in ["TLSv1.3", "TLSv1.2"] else "WEAK_TLS"
                }
    except Exception as e:
        return {"https_Supported": False, "status": "CRITICAL_SSL_FAILURE", "error": str(e)}

def check_dns_posture(domain: str) -> dict:
    """Checks SPF and DMARC records to detect Email Spoofing / Phishing exposure."""
    dns_findings = {"spf_present": False, "dmarc_present": False, "issues": []}
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for rec in txt_records:
            if "v=spf1" in rec.to_text():
                dns_findings["spf_present"] = True
    except Exception:
        pass

    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rec in dmarc_records:
            if "v=DMARC1" in rec.to_text():
                dns_findings["dmarc_present"] = True
    except Exception:
        pass

    if not dns_findings["spf_present"]:
        dns_findings["issues"].append("Missing SPF record (Vulnerable to domain email spoofing)")
    if not dns_findings["dmarc_present"]:
        dns_findings["issues"].append("Missing DMARC record (No anti-phishing policy enforced)")

    return dns_findings

def run_security_audit(target_url: str, authorized_deep_scan: bool = False) -> dict:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    domain = clean_domain(target_url)
    report = {
        "target": target_url,
        "domain": domain,
        "scan_tier": "AUTHORIZED_DEEP_AUDIT" if authorized_deep_scan else "PUBLIC_PASSIVE_SCAN",
        "tls_posture": check_tls_security(domain),
        "dns_posture": check_dns_posture(domain),
        "missing_headers": [],
        "information_leakage": [],
        "cookie_flaws": [],
        "cors_issue": None,
        "endpoint_exposure": []
    }

    try:
        with httpx.Client(follow_redirects=True, timeout=8.0, headers={"User-Agent": "AegisAI-Security-Auditor/2.0"}) as client:
            res = client.get(target_url)
            headers = {k.lower(): v for k, v in res.headers.items()}

            # 1. Security Headers Audit
            required_headers = {
                "content-security-policy": "HIGH - Mitigates Cross-Site Scripting (XSS) & Data Injection",
                "strict-transport-security": "HIGH - Enforces HTTPS & prevents SSL Stripping (HSTS)",
                "x-frame-options": "MEDIUM - Protects against Clickjacking attacks",
                "x-content-type-options": "LOW - Prevents MIME-type sniffing (`nosniff`)",
                "referrer-policy": "LOW - Controls sensitive URL leakage in Referer header",
                "permissions-policy": "LOW - Restricts browser hardware APIs (Camera, Mic, Geolocation)"
            }

            for h, impact in required_headers.items():
                if h not in headers:
                    report["missing_headers"].append({"header": h, "impact": impact})

            # 2. Server Tech-Stack Information Leakage
            for leak_h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
                if leak_h in headers:
                    report["information_leakage"].append(f"{leak_h}: {headers[leak_h]}")

            # 3. CORS Misconfiguration Check
            acao = headers.get("access-control-allow-origin")
            if acao == "*":
                report["cors_issue"] = "Wildcard CORS ('*') detected - Public APIs may expose data to arbitrary origins."

            # 4. Deep Scan Checks (Only runs if Authorized!)
            if authorized_deep_scan:
                # Cookie Security Inspection
                for cookie in res.cookies.jar:
                    flaws = []
                    if not cookie.secure:
                        flaws.append("Missing 'Secure' flag")
                    if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
                        flaws.append("Missing 'HttpOnly' flag (Exposed to XSS theft)")
                    if flaws:
                        report["cookie_flaws"].append({"cookie_name": cookie.name, "flaws": flaws})

                # Check standard governance & config endpoints
                for path in ["/.well-known/security.txt", "/robots.txt", "/sitemap.xml"]:
                    try:
                        p_res = client.get(f"https://{domain}{path}")
                        if p_res.status_code == 200:
                            report["endpoint_exposure"].append({
                                "path": path,
                                "status": 200,
                                "note": "Accessible public file"
                            })
                    except Exception:
                        pass

    except Exception as e:
        report["http_error"] = str(e)

    return report