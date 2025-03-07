import requests
import json
import textwrap
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def get_cve_info(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=100)  # Set timeout to 10 seconds
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)
    except requests.RequestException as e:
        print(f"Error: Unable to fetch CVE data: {e}")
        return None

    data = response.json()

    if not data.get("vulnerabilities"):
        print("Error: No CVE data found.")
        return None

    cve_data = data["vulnerabilities"][0]["cve"]
    description = next((desc["value"] for desc in cve_data.get("descriptions", []) if desc.get("value")), "N/A")
    published = cve_data.get("published", "N/A")
    modified = cve_data.get("lastModified", "N/A")

    cvss_data = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
    base_score = cvss_data.get("baseScore", "N/A")

    severity = "N/A"
    if isinstance(base_score, (int, float)):
        severity = "Low" if base_score < 4.0 else "Medium" if base_score < 7.0 else "High" if base_score < 9.0 else "Critical"

    vector_string = cvss_data.get("vectorString", "")
    vector_parts = {key: "N/A" for key in ["AC", "C", "I", "A"]}

    for part in vector_string.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            if key in vector_parts:
                vector_parts[key] = value

    cwe_ids = ", ".join(
        desc["value"] for weakness in cve_data.get("weaknesses", []) for desc in weakness.get("description", []) if
        desc.get("value")) or "N/A"

    return {
        "CVE Number": cve_id,
        "Description": description,
        "Published Date": published,
        "Modified Date": modified,
        "CVSS Base Score": base_score,
        "Severity": severity,
        "CVSS Vector AC": vector_parts["AC"],
        "CVSS Vector C": vector_parts["C"],
        "CVSS Vector I": vector_parts["I"],
        "CVSS Vector A": vector_parts["A"],
        "CWE-IDs": cwe_ids,
    }


def create_pdf(cve_info):
    filename = f"{cve_info['CVE Number']}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y_position = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y_position, "CVE Report")
    y_position -= 30

    c.setFont("Helvetica", 12)
    text_object = c.beginText(50, y_position)
    text_object.setFont("Helvetica", 12)

    for key, value in cve_info.items():
        wrapped_text = textwrap.wrap(f"{key}: {value}", width=90)
        text_object.textLines("\n".join(wrapped_text))  # Efficient line wrapping
        text_object.textLine("")

    c.drawText(text_object)
    c.save()
    print(f"PDF saved as {filename}")


def main():
    cve_id = input("Enter a CVE number (e.g., CVE-2024-1234): ")
    cve_info = get_cve_info(cve_id)

    if cve_info:
        create_pdf(cve_info)
    else:
        print("No valid CVE information found.")


if __name__ == "__main__":
    main()