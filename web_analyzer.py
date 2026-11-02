
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

class RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.history = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.history.append(newurl)
        return super().redirect_request(
            req, fp, code, msg, headers, newurl
        )

print("=" * 50)
print(" CYBERLAB ADVANCED WEBSITE ANALYZER V3.0")
print("=" * 50)

url = input("\nEnter HTTPS Website URL: ").strip()

if not url.startswith(("https://", "http://")):
    url = "https://" + url

parsed = urlsplit(url)
host = parsed.hostname

if parsed.scheme not in ("https", "http") or not host:
    print("Invalid URL!")
    raise SystemExit

show("\nTARGET: " + url)
show("\n--- 1. DNS ANALYSIS ---")

try:
    results = socket.getaddrinfo(
        host, None, type=socket.SOCK_STREAM
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
            (host, 443), timeout=8
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=host
            ) as tls_socket:

                cert = tls_socket.getpeercert()
                show("TLS Version: " + str(tls_socket.version()))
                show("Cipher: " + str(tls_socket.cipher()[0]))

                issuer = cert.get("issuer", ())
                show("Certificate Issuer: " + str(issuer))

                expiry = cert.get("notAfter")
                if expiry:
                    expiry_time = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(expiry),
                        timezone.utc
                    )
                    show("Certificate Expires: " + str(expiry_time))
                    show("Certificate Expiry Check: " +
                         ("VALID" if expiry_time > datetime.now(
                             timezone.utc) else "EXPIRED"))

                show("SSL Certificate: VERIFIED")

    except (OSError, ssl.SSLError, ValueError) as error:
        show("SSL ERROR: " + str(error))
else:
    show("SSL CHECK: Skipped (URL uses HTTP)")

show("\n--- 3. HTTP / HTTPS ANALYSIS ---")

tracker = RedirectTracker()
opener = urllib.request.build_opener(tracker)

request = urllib.request.Request(
    url,
    headers={"User-Agent": "CyberLab-Analyzer/3.0"},
    method="GET"
)

response_headers = None
status = None
final_url = url

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
    show("HTTPS Active: " + str(
        final_url.startswith("https://")
    ))

show("\n--- 4. REDIRECT ANALYSIS ---")

if tracker.history:
    for index, address in enumerate(tracker.history, 1):
        show("Redirect " + str(index) + ": " + address)
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
    show("Headers unavailable.")

show("\n--- 6. FINAL SUMMARY ---")
show("Headers Found: " + str(found))
show("Headers Missing: " + str(missing))
show("Total Headers Checked: " + str(found + missing))

show("\nNote: Missing headers alone do not prove a vulnerability.")

filename = "web_analyzer_report.txt"

with open(filename, "w") as file:
    file.write("CYBERLAB V3.0 SECURITY REPORT\n")
    file.write("Date: " + str(datetime.now()) + "\n\n")
    file.write("\n".join(report))

print("\nReport saved: " + filename)
print("\nANALYSIS COMPLETED!")

