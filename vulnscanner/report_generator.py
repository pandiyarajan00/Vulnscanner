from fpdf import FPDF
from urllib.parse import urlparse

def create_pdf_report(url, findings):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)

    # Add title
    pdf.cell(0, 10, "Vulnerability Scan Report", ln=1, align='C')
    pdf.ln(10)

    # Add scanned URL
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f"Scanned URL: {url}", ln=1)
    pdf.ln(5)

    # Add each finding
    for key, value in findings.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(0, 102, 204)
        pdf.cell(0, 10, f"{key}:", ln=1)

        pdf.set_font("Arial", '', 11)
        pdf.set_text_color(0, 0, 0)
        if isinstance(value, list):
            if value:
                for item in value:
                    pdf.cell(0, 8, f"- {item}", ln=1)
            else:
                pdf.cell(0, 8, "None", ln=1)
        else:
            pdf.cell(0, 8, str(value), ln=1)

        pdf.ln(5)

    # Create filename based on hostname
    hostname = urlparse(url).hostname.replace('.', '_')
    filename = f"report_{hostname}.pdf"

    # Save file
    pdf.output(filename)

    print(f"✅ Report saved as {filename}")
