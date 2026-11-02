import urllib.request
import urllib.error
from urllib.parse import urlsplit
from datetime import datetime

print("=" * 45)
print(" CYBERLAB WEBSITE HEADER CHECKER V2.0")
print("=" * 45)

url = input("Enter Website URL: ").strip()

if not url.startswith(("https://", "http://")):
    url = "https://" + url

parsed = urlsplit(url)

if parsed.scheme not in ("https", "http") or not parsed.hostname:
    print("Invalid URL!")
    raise SystemExit

headers_to_check = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

found = []
missing = []
status = None
final_url = url

request = urllib.request.Request(
    url,
    headers={"User-Agent": "CyberLab-HeaderChecker/2.0"}
)

try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status = response.status
        final_url = response.url
        response_headers = response.headers

except urllib.error.HTTPError as error:
    status = error.code
    final_url = error.url
    response_headers = error.headers

except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
    print("\nConnection Error:", error)
    raise SystemExit

print("\nWebsite:", final_url)
print("HTTP Status:", status)
print("HTTPS:", "YES" if final_url.startswith("https://") else "NO")

print("\n" + "=" * 45)
print(" SECURITY HEADERS REPORT")
print("=" * 45)

report = []

for header in headers_to_check:
    value = response_headers.get(header)

    if value:
        found.append(header)
        result = "[FOUND] " + header + ": " + value
    else:
        missing.append(header)
        result = "[MISSING] " + header

    print(result)
    report.append(result)

print("\n" + "=" * 45)
print(" SUMMARY")
print("=" * 45)

print("Headers Found:", len(found))
print("Headers Missing:", len(missing))
print("Total Checked:", len(headers_to_check))

print("\nNote: Missing headers alone do not prove a vulnerability.")

with open("header_report.txt", "w") as file:
    file.write("CYBERLAB SECURITY REPORT\n")
    file.write("Date: " + str(datetime.now()) + "\n")
    file.write("Website: " + final_url + "\n")
    file.write("HTTP Status: " + str(status) + "\n")
    file.write("HTTPS: " + str(final_url.startswith("https://")) + "\n\n")

    for item in report:
        file.write(item + "\n")

    file.write("\nFound: " + str(len(found)))
    file.write("\nMissing: " + str(len(missing)))

print("\nReport saved: header_report.txt")
print("\nCHECK COMPLETED!")
