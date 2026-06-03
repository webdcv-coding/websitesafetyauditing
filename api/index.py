from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests

# Session helps with speed; max_redirects prevents "Forever" loops
session = requests.Session()
session.max_redirects = 3

def get_audit_results(domain):
    # Clean input: remove protocol if user pasted it
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0].strip()
    url = f"https://{domain}"
    
    score = 100
    vulnerabilities = []
    headers = {}
    
    # Professional User-Agent to prevent bot-blocking
    custom_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }

    try:
        # stream=True is the 'magic'—it grabs headers without waiting for the whole page to load
        response = session.get(url, timeout=6, verify=True, allow_redirects=True, headers=custom_headers, stream=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        response.close() 
    
    except requests.exceptions.SSLError:
        score -= 47
        vulnerabilities.append({
            "name": "SSL Issues Detected",
            "description": "Encryption is broken or missing. User data could be at risk."
        })
        try:
            # Quick fallback check if SSL is the only problem
            low_sec_res = session.get(url, timeout=4, verify=False, allow_redirects=True, headers=custom_headers, stream=True)
            headers = {k.lower(): v for k, v in low_sec_res.headers.items()}
            low_sec_res.close()
        except:
            pass

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return {"score": 0, "vulnerabilities": [{"name": "Unreachable", "description": "The site took too long to respond or doesn't exist."}]}
    except Exception:
        return {"score": 0, "vulnerabilities": [{"name": "Scan Error", "description": "Check domain spelling and try again."}]}

    if not headers:
        return {"score": 0, "vulnerabilities": [{"name": "No Data", "description": "The server responded but provided no security headers."}]}

    # --- Header Logic ---
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        score -= 17 
        vulnerabilities.append({"name": "Missing Clickjacking Shield", "description": "Protection against being embedded in malicious frames is missing."})

    if "strict-transport-security" not in headers:
        score -= 12
        vulnerabilities.append({"name": "HSTS Not Active", "description": "Browser is not forced to use HTTPS for all requests."})

    if "x-content-type-options" not in headers:
        score -= 12
        vulnerabilities.append({"name": "Missing Sniffing Protection", "description": "Prevents browsers from incorrectly interpreting file types."})

    return {
        "score": max(0, score),
        "vulnerabilities": vulnerabilities
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        domain = params.get("domain", [None])[0]

        if not domain:
            self.send_response(400)
            self.end_headers()
            return

        result = get_audit_results(domain)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())
