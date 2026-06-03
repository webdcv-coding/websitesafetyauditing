# WebShield 🛡️

A minimalist security header auditor designed to help website owners identify missing protection protocols.

## How it works
This tool performs a non-invasive scan of a domain's HTTP headers. It checks for:
* **SSL Validity:** Ensures traffic is encrypted.
* **HSTS:** Checks if the site forces secure connections.
* **X-Frame-Options:** Detects protection against Clickjacking.
* **X-Content-Type-Options:** Checks for MIME-sniffing protection.

## Why Open Source?
I built this tool to provide transparency. Many security scanners are "black boxes"—WebShield is open so that:
1. You can see exactly how the scoring math works.
2. You can verify that the scan is non-destructive and only reads public headers.
3. You can see that a score of 100 is achievable with proper configuration.

## Built With
* Python (Requests)
* JavaScript (Fetch API)
* Tailwind CSS
