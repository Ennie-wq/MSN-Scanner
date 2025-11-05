import nmap
import re
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sS -sV -O -Pn --script vuln")
    return nm

def parse_vuln_output(output):
    """Extract CVEs, severity, and create recommendation from script output."""
    findings = {}
    
    # Extract CVEs
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", output)
    if cves:
        findings["CVEs"] = cves
    else:
        findings["CVEs"] = []

    # Detect severity keywords
    severity = "Info"
    if re.search(r"(critical|severe)", output, re.I):
        severity = "Critical"
    elif re.search(r"(high)", output, re.I):
        severity = "High"
    elif re.search(r"(medium)", output, re.I):
        severity = "Medium"
    elif re.search(r"(low)", output, re.I):
        severity = "Low"
    findings["Severity"] = severity

    # Add a generic recommendation
    if findings["CVEs"]:
        findings["Recommendation"] = "Apply the latest patches and security updates for the affected software. Review vendor advisories for the listed CVEs."
    else:
        findings["Recommendation"] = "Review service configuration and apply vendor hardening guides."

    return findings

def generate_report(target, nm):
    doc = SimpleDocTemplate(f"{target}_deep_scan_report.pdf")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"<b>MSN Deep Vulnerability Scan Report for {target}</b>", styles["Title"]))
    story.append(Spacer(1, 12))

    for host in nm.all_hosts():
        story.append(Paragraph(f"<b>Host:</b> {host} ({nm[host].hostname()})", styles["Normal"]))
        story.append(Paragraph(f"<b>Status:</b> {nm[host].state()}", styles["Normal"]))

        # OS detection
        if "osmatch" in nm[host]:
            if nm[host]["osmatch"]:
                os_name = nm[host]["osmatch"][0]["name"]
                story.append(Paragraph(f"<b>Detected OS:</b> {os_name}", styles["Normal"]))
            else:
                story.append(Paragraph("<b>Detected OS:</b> Unknown", styles["Normal"]))
        story.append(Spacer(1, 12))

        # Open Ports Table
        story.append(Paragraph("<b>Open Ports & Services</b>", styles["Heading2"]))
        port_data = [["Port", "State", "Service", "Product", "Version"]]

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]["name"]
                product = nm[host][proto][port].get("product", "")
                version = nm[host][proto][port].get("version", "")
                state = nm[host][proto][port]["state"]
                port_data.append([str(port), state, service, product, version])

        if len(port_data) == 1:
            port_data.append(["-", "-", "-", "-", "-"])

        table = Table(port_data, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(table)
        story.append(Spacer(1, 12))

        # Vulnerability Findings
        story.append(Paragraph("<b>Vulnerability Findings</b>", styles["Heading2"]))
        vuln_data = [["Port", "Detection Name", "Severity", "CVEs", "Recommendation"]]

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                scripts = nm[host][proto][port].get("script", {})
                if scripts:
                    for script, output in scripts.items():
                        parsed = parse_vuln_output(output)
                        cve_links = ", ".join([f"<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={c}'> {c}</a>" for c in parsed["CVEs"]]) if parsed["CVEs"] else "None"
                        vuln_data.append([
                            str(port),
                            script,
                            parsed["Severity"],
                            cve_links,
                            parsed["Recommendation"]
                        ])
        
        if len(vuln_data) == 1:
            vuln_data.append(["-", "No vulnerabilities detected", "-", "-", "-"])

        vuln_table = Table(vuln_data, hAlign="LEFT", colWidths=[50, 120, 70, 150, 200])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 24))

    doc.build(story)
    print(f"✅ Report generated: {target}_deep_scan_report.pdf")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    print(f"[*] Running deep scan on {target} (Ports + Services + OS + Vulns)...")
    results = scan_target(target)
    generate_report(target, results)
