import socket

print("=" * 35)
print("     CYBERLAB PORT CHECKER")
print("=" * 35)

host = input("Enter your lab IP: ").strip()

ports = [21, 22, 53, 80, 443, 8080]

try:
    ip = socket.gethostbyname(host)
    print("\nTarget:", ip)

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((ip, port))

        if result == 0:
            print(f"[OPEN] Port {port}")
        else:
            print(f"[CLOSED/FILTERED] Port {port}")

        s.close()

except socket.gaierror:
    print("Invalid hostname or DNS error")

print("\nCHECK COMPLETED")

