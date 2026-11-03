
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from datetime import datetime, timezone

HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

report = []

def show(message):
    print(message)
    report.append(str(message))

def format_name(name):
    parts = []
    for group in name:
        for key, value in group:
            parts.append(str(key) + "=" + str(value))
    return ", ".join(parts) if parts else "Unavailable"

class RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.history = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.history.append({
            "status": code,
            "url": newurl
        })
        return super().redirect_request(
            req, fp, code, msg, headers, newurl
        )

print("=" * 52)
print(" CYBERLAB ADVANCED WEBSITE SECURITY ANALYZER V4.0")
print("=" * 52)

url = input("\nEnter Website URL: ").strip()

if not url.startswith(("https://", "http://")):
    url = "https://" + url

try:
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port
except ValueError as error:
    print("Invalid URL:", error)
    raise SystemExit

if parsed.scheme not in ("https", "http") or not host:
    print("Invalid URL!")
    raise SystemExit

if parsed.username or parsed.password:
    print("URLs containing credentials are not allowed.")
    raise SystemExit

if port is None:
    port = 443 if parsed.scheme == "https" else 80

if not (1 <= port <= 65535):
    print("Invalid port!")
    raise SystemExit

show("\nTARGET: " + url)
show("HOST: " + host)
show("PORT: " + str(port))

show("\n--- 1. DNS ANALYSIS ---")

try:
    results = socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    )
    ips = sorted({item[4][0] for item in results})

    for ip in ips:
        show("DNS IP: " + ip)

except socket.gaierror as error:
    show("DNS ERROR: " + str(error))

show("\n--- 2. SSL/TLS ANALYSIS ---")

if parsed.scheme == "https":
    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port), timeout=8
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket, server_hostname=host
            ) as tls_socket:

                cert = tls_socket.getpeercert()

                show("TLS Version: " + str(tls_socket.version()))
                show("Cipher: " + str(tls_socket.cipher()[0]))

                show("Certificate Subject: " +
                     format_name(cert.get("subject", ())))

                show("Certificate Issuer: " +
                     format_name(cert.get("issuer", ())))

                expiry = cert.get("notAfter")

                if expiry:
                    expiry_time = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(expiry),
                        timezone.utc
                    )

                    show("Certificate Expires: " + str(expiry_time))

                    if expiry_time > datetime.now(timezone.utc):
                        show("Certificate Expiry: VALID")
                    else:
                        show("Certificate Expiry: EXPIRED")

                show("Hostname Verification: PASSED")
                show("Certificate Verification: PASSED")

    except (OSError, ssl.SSLError, ValueError) as error:
        show("SSL/TLS ERROR: " + str(error))

else:
    show("SSL/TLS: Skipped (HTTP URL)")

show("\n--- 3. HTTP ANALYSIS ---")

tracker = RedirectTracker()
opener = urllib.request.build_opener(tracker)

request = urllib.request.Request(
    url,
    headers={"User-Agent": "CyberLab-Analyzer/3.1"},
    method="GET"
)

status = None
final_url = url
response_headers = None

try:
    with opener.open(request, timeout=12) as response:
        status = response.status
        final_url = response.url
        response_headers = response.headers

except urllib.error.HTTPError as error:
    status = error.code
    final_url = error.url
    response_headers = error.headers

except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
    show("HTTP CONNECTION ERROR: " + str(error))

if status is not None:
    show("HTTP Status: " + str(status))
    show("Final URL: " + final_url)
    show("Final HTTPS: " + str(
        final_url.startswith("https://")
    ))

show("\n--- 4. REDIRECT ANALYSIS ---")

show("Redirect Count: " + str(len(tracker.history)))

if tracker.history:
    for index, item in enumerate(tracker.history, 1):
        show(
            str(index) + ". HTTP " +
            str(item["status"]) + " -> " + item["url"]
        )
else:
    show("No redirects detected.")

show("\n--- 5. SECURITY HEADERS ---")

found = 0
missing = 0

if response_headers:
    for header in HEADERS:
        value = response_headers.get(header)

        if value:
            found += 1
            show("[FOUND] " + header + ": " + value)
        else:
            missing += 1
            show("[MISSING] " + header)
else:
    show("Security headers unavailable.")


show("\n--- 6. COOKIE SECURITY ANALYSIS ---")

cookies = response_headers.get_all("Set-Cookie", []) if response_headers else []

if not cookies:
    show("No Set-Cookie headers detected.")
else:
    for index, cookie in enumerate(cookies, 1):
        parts = [part.strip() for part in cookie.split(";")]
        name = parts[0].split("=", 1)[0] if parts else "Unknown"

        attrs = {}
        for part in parts[1:]:
            key, _, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip()

        show("Cookie " + str(index) + ": " + name)

        if "secure" in attrs:
            show("[FOUND] Secure")
        else:
            show("[REVIEW] Secure flag missing")

        if "httponly" in attrs:
            show("[FOUND] HttpOnly")
        else:
            show("[REVIEW] HttpOnly flag missing")

        if "samesite" in attrs:
            show("SameSite: " + attrs["samesite"])
        else:
            show("[REVIEW] SameSite attribute missing")

        if attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
            show("[WARNING] SameSite=None without Secure")

show("\n--- 7. FINAL SUMMARY ---")
show("Headers Found: " + str(found))
show("Headers Missing: " + str(missing))
show("Total Checked: " + str(found + missing))

show("\nNote: Missing headers alone do not prove a vulnerability.")
show("TLS verification uses the device's trusted CA certificates.")

filename = "web_analyzer_v4_report.txt"

try:
    with open(filename, "w") as file:
        file.write("CYBERLAB V4.0 SECURITY REPORT\n")
        file.write("Date: " + str(datetime.now().astimezone()) + "\n\n")
        file.write("\n".join(report) + "\n")

    print("\nReport saved:", filename)

except OSError as error:
    print("Report save error:", error)

print("\nANALYSIS COMPLETED!")

