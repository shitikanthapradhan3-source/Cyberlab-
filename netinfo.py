import socket
import platform

print("=" * 35)
print("    CYBERLAB NETWORK TOOL")
print("=" * 35)

print("Device:", platform.machine())
print("System:", platform.system())
print("Hostname:", socket.gethostname())

# Local IP address
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    print("Local IP:", s.getsockname()[0])
    s.close()
except Exception:
    print("Local IP: Not available")

# DNS Lookup
domain = "example.com"

try:
    ip = socket.gethostbyname(domain)
    print("DNS Lookup:", domain)
    print("Resolved IP:", ip)
except Exception:
    print("DNS Lookup failed")

print("=" * 35)
print("       SCAN COMPLETED")
print("=" * 35)
