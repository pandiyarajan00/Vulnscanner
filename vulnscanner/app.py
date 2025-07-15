import streamlit as st
from scanner import check_security_headers, check_directory_listing, get_server_banner, run_nmap_scan
from report_generator import create_pdf_report
from urllib.parse import urlparse
import os

st.set_page_config(page_title="VulnScanner", page_icon="🔍")
st.title("🔍 VulnScanner - Simple Web Vulnerability Scanner")

url = st.text_input("Enter website URL (e.g., http://example.com)")

if st.button("Start Scan"):
    if url:
        host = urlparse(url).hostname
        st.info(f"🔧 Scanning {url} ... Please wait.")

        missing_headers = check_security_headers(url)
        directory_listing = check_directory_listing(url)
        server = get_server_banner(url)
        ports = run_nmap_scan(host)

        findings = {
            'Missing Security Headers': missing_headers,
            'Open Directory Listing': directory_listing,
            'Server Banner': server,
            'Open Ports': ports
        }

        # Generate PDF
        create_pdf_report(url, findings)

        filename = f"report_{host.replace('.', '_')}.pdf"

        st.success("✅ Scan completed successfully!")
        st.write("### Findings:")
        st.json(findings)

        if os.path.exists(filename):
            with open(filename, "rb") as f:
                st.download_button(
                    label="📄 Download PDF Report",
                    data=f,
                    file_name=filename,
                    mime="application/pdf"
                )
        else:
            st.error("❌ Report file not found.")
    else:
        st.warning("⚠️ Please enter a valid URL.")
