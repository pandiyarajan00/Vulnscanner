import requests
import nmap
from urllib.parse import urlparse
from report_generator import create_pdf_report

def check_security_headers(url):
    expected_headers = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Content-Security-Policy',
        'Strict-Transport-Security'
    ]
    try:
        response = requests.get(url, timeout=10)
        missing = [h for h in expected_headers if h not in response.headers]
        return missing
    except Exception as e:
        print(f"Error checking security headers: {e}")
        return []

def check_directory_listing(url):
    try:
        response = requests.get(url, timeout=10)
        if "Index of /" in response.text:
            return True
        return False
    except Exception as e:
        print(f"Error checking directory listing: {e}")
        return False

def get_server_banner(url):
    try:
        response = requests.get(url, timeout=10)
        return response.headers.get('Server', 'Unknown')
    except Exception as e:
        print(f"Error getting server banner: {e}")
        return 'Unknown'

def run_nmap_scan(host):
    nm = nmap.PortScanner()
    print("[*] Running Nmap scan on host...")
    try:
        nm.scan(host, arguments='-F')  # Fast scan
        open_ports = []
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    open_ports.append(f"{proto}/{port}")
        return open_ports
    except Exception as e:
        print(f"Error running nmap scan: {e}")
        return []

def main():
    url = input("Enter website URL (e.g., http://example.com): ").strip()

    host = urlparse(url).hostname

    print("[*] Checking security headers...")
    missing_headers = check_security_headers(url)

    print("[*] Checking for open directory listing...")
    directory_listing = check_directory_listing(url)

    print("[*] Getting server banner...")
    server = get_server_banner(url)

    print("[*] Running Nmap port scan...")
    ports = run_nmap_scan(host)

    findings = {
        'Missing Security Headers': missing_headers,
        'Open Directory Listing': directory_listing,
        'Server Banner': server,
        'Open Ports': ports
    }

    print("[*] Generating PDF report...")
    create_pdf_report(url, findings)

    print("✅ Scan completed. Report saved as report.pdf")

if __name__ == "__main__":
    main()
