import urllib.request
import urllib.error
import socket
import ssl

def get_audit_results(domain):
    # DNS Verification
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        return {
            "score": 0,
            "vulnerabilities": [{
                "name": "Domain Inactive",
                "description": "This domain could not be resolved. Verify the spelling."
            }]
        }

    score = 100
    vulnerabilities = []

    ctx = ssl.create_default_context()

    req = urllib.request.Request(
        f"https://{domain}/",
        headers={
            "User-Agent": "Mozilla/5.0"
        }
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            headers = {k.lower(): v for k, v in response.getheaders()}

    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}

    except Exception:
        score -= 40
        vulnerabilities.append({
            "name": "SSL Missing or Broken",
            "description": "Failed to establish a secure HTTPS connection."
        })

        return {
            "score": max(0, score),
            "vulnerabilities": vulnerabilities
        }

    # Clickjacking Protection
    if (
        "x-frame-options" not in headers
        and "content-security-policy" not in headers
    ):
        score -= 25
        vulnerabilities.append({
            "name": "Missing Clickjacking Protection",
            "description": "Missing X-Frame-Options and Content-Security-Policy headers."
        })

    # Content Type Protection
    if "x-content-type-options" not in headers:
        score -= 15
        vulnerabilities.append({
            "name": "Missing X-Content-Type-Options",
            "description": "The browser may perform MIME-type sniffing."
        })

    # Referrer Policy
    if "referrer-policy" not in headers:
        score -= 10
        vulnerabilities.append({
            "name": "Missing Referrer Policy",
            "description": "The site does not control referrer information sent to other sites."
        })

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }
