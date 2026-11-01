import urllib.request
from urllib.error import URLError, HTTPError

print("=" * 40)
print(" CYBERLAB WEBSITE HEADER CHECKER")
print("=" * 40)

url = input("Enter website URL: ").strip()

if not url.startswith(("https://", "http://")):
    url = "https://" + url

headers_to_check = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

try:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CyberLab-HeaderChecker/1.0"},
        method="GET"
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        print("\nWebsite:", response.url)
        print("HTTP Status:", response.status)

        print("\n--- SECURITY HEADERS ---")

        for header in headers_to_check:
            value = response.headers.get(header)

            if value:
                print("[FOUND]", header, ":", value)
            else:
                print("[MISSING]", header)

except (URLError, HTTPError, TimeoutError, ValueError) as error:
    print("Connection Error:", error)

print("\nCHECK COMPLETED")

