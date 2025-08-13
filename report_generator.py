#!/usr/bin/env python3
"""
Report Generator for Web Vulnerability Scanner
Generates structured reports in multiple formats (TXT, HTML, MD, JSON)
"""

import os
import json
from datetime import datetime
from typing import Dict, List
from jinja2 import Template
import webbrowser
from scanner import ScanResult, Vulnerability, RiskLevel

class ReportGenerator:
    """Generates vulnerability scan reports in multiple formats"""
    
    def __init__(self):
        self.reports_dir = "reports"
        self._ensure_reports_directory()
    
    def _ensure_reports_directory(self):
        """Create reports directory if it doesn't exist"""
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate_report(self, scan_result: ScanResult, output_format: str = 'txt'):
        """Generate report in the specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = scan_result.target_url.replace("://", "_").replace("/", "_").replace(".", "_")
        filename = f"vuln_scan_{target_name}_{timestamp}"
        
        if output_format == 'txt':
            return self._generate_txt_report(scan_result, filename)
        elif output_format == 'html':
            return self._generate_html_report(scan_result, filename)
        elif output_format == 'md':
            return self._generate_markdown_report(scan_result, filename)
        elif output_format == 'json':
            return self._generate_json_report(scan_result, filename)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_txt_report(self, scan_result: ScanResult, filename: str) -> str:
        """Generate plain text report"""
        report_path = os.path.join(self.reports_dir, f"{filename}.txt")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WEB APPLICATION VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Scan Information
            f.write("SCAN INFORMATION\n")
            f.write("-" * 40 + "\n")
            f.write(f"Target URL: {scan_result.target_url}\n")
            f.write(f"Scan Timestamp: {scan_result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {scan_result.scan_duration:.2f} seconds\n")
            f.write(f"Total Pages Discovered: {len(scan_result.discovered_pages)}\n")
            f.write(f"Total Forms Found: {len(scan_result.discovered_forms)}\n")
            f.write(f"Total Vulnerabilities: {len(scan_result.vulnerabilities)}\n\n")
            
            # Software Stack
            if scan_result.software_stack:
                f.write("SOFTWARE STACK DETECTED\n")
                f.write("-" * 40 + "\n")
                for tech, info in scan_result.software_stack.items():
                    f.write(f"{tech}: {info}\n")
                f.write("\n")
            
            # Security Headers
            if scan_result.security_headers:
                f.write("SECURITY HEADERS\n")
                f.write("-" * 40 + "\n")
                for header, value in scan_result.security_headers.items():
                    f.write(f"{header}: {value}\n")
                f.write("\n")
            
            # Cookies
            if scan_result.cookies:
                f.write("COOKIES\n")
                f.write("-" * 40 + "\n")
                for cookie in scan_result.cookies:
                    f.write(f"Name: {cookie['name']}\n")
                    f.write(f"  Value: {cookie['value'][:50]}...\n")
                    f.write(f"  Secure: {cookie['secure']}\n")
                    f.write(f"  HttpOnly: {cookie['httponly']}\n")
                    f.write(f"  Domain: {cookie['domain']}\n")
                    f.write(f"  Path: {cookie['path']}\n\n")
            
            # Discovered Pages
            if scan_result.discovered_pages:
                f.write("DISCOVERED PAGES\n")
                f.write("-" * 40 + "\n")
                for page in scan_result.discovered_pages:
                    f.write(f"  {page}\n")
                f.write("\n")
            
            # Discovered Forms
            if scan_result.discovered_forms:
                f.write("DISCOVERED FORMS\n")
                f.write("-" * 40 + "\n")
                for i, form in enumerate(scan_result.discovered_forms, 1):
                    f.write(f"Form {i}:\n")
                    f.write(f"  Page: {form['page_url']}\n")
                    f.write(f"  Action: {form['action']}\n")
                    f.write(f"  Method: {form['method']}\n")
                    f.write(f"  Inputs: {len(form['inputs'])}\n")
                    for inp in form['inputs']:
                        f.write(f"    - {inp['type']}: {inp['name']} (ID: {inp['id']})\n")
                    f.write("\n")
            
            # Vulnerabilities
            if scan_result.vulnerabilities:
                f.write("VULNERABILITY FINDINGS\n")
                f.write("-" * 40 + "\n")
                
                # Group by risk level
                risk_groups = {}
                for vuln in scan_result.vulnerabilities:
                    risk = vuln.risk_level.value
                    if risk not in risk_groups:
                        risk_groups[risk] = []
                    risk_groups[risk].append(vuln)
                
                # Sort by risk level (Critical -> High -> Medium -> Low -> Info)
                risk_order = ['Critical', 'High', 'Medium', 'Low', 'Information']
                
                for risk_level in risk_order:
                    if risk_level in risk_groups:
                        f.write(f"\n{risk_level.upper()} RISK VULNERABILITIES\n")
                        f.write("-" * len(risk_level) + "\n")
                        
                        for vuln in risk_groups[risk_level]:
                            f.write(f"Name: {vuln.name}\n")
                            f.write(f"Description: {vuln.description}\n")
                            f.write(f"Risk Level: {vuln.risk_level.value}\n")
                            f.write(f"Location: {vuln.location}\n")
                            f.write(f"Evidence: {vuln.evidence}\n")
                            f.write(f"Recommendation: {vuln.recommendation}\n")
                            if vuln.cwe_id:
                                f.write(f"CWE ID: {vuln.cwe_id}\n")
                            f.write("\n")
            else:
                f.write("VULNERABILITY FINDINGS\n")
                f.write("-" * 40 + "\n")
                f.write("No vulnerabilities detected during this scan.\n\n")
            
            # Summary
            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Scan completed successfully for {scan_result.target_url}\n")
            f.write(f"Total vulnerabilities found: {len(scan_result.vulnerabilities)}\n")
            
            if scan_result.vulnerabilities:
                critical_count = sum(1 for v in scan_result.vulnerabilities if v.risk_level == RiskLevel.CRITICAL)
                high_count = sum(1 for v in scan_result.vulnerabilities if v.risk_level == RiskLevel.HIGH)
                medium_count = sum(1 for v in scan_result.vulnerabilities if v.risk_level == RiskLevel.MEDIUM)
                low_count = sum(1 for v in scan_result.vulnerabilities if v.risk_level == RiskLevel.LOW)
                
                f.write(f"Critical: {critical_count}\n")
                f.write(f"High: {high_count}\n")
                f.write(f"Medium: {medium_count}\n")
                f.write(f"Low: {low_count}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by Web Vulnerability Scanner\n")
            f.write("=" * 80 + "\n")
        
        print(f"Text report generated: {report_path}")
        return report_path
    
    def _generate_html_report(self, scan_result: ScanResult, filename: str) -> str:
        """Generate HTML report"""
        report_path = os.path.join(self.reports_dir, f"{filename}.html")
        
        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {{ scan_result.target_url }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #e74c3c; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #e74c3c; margin: 0; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .vulnerability { background: #f8f9fa; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .vulnerability.critical { border-left-color: #e74c3c; background: #fdf2f2; }
        .vulnerability.high { border-left-color: #f39c12; background: #fef9e7; }
        .vulnerability.medium { border-left-color: #f1c40f; background: #fefce8; }
        .vulnerability.low { border-left-color: #27ae60; background: #f0f9f0; }
        .vulnerability.info { border-left-color: #3498db; background: #f0f8ff; }
        .risk-badge { display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
        .risk-critical { background: #e74c3c; }
        .risk-high { background: #f39c12; }
        .risk-medium { background: #f1c40f; color: #2c3e50; }
        .risk-low { background: #27ae60; }
        .risk-info { background: #3498db; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .url-list { background: #f8f9fa; padding: 15px; border-radius: 4px; }
        .url-list a { color: #3498db; text-decoration: none; }
        .url-list a:hover { text-decoration: underline; }
        .form-details { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .input-field { margin: 5px 0; padding: 5px; background: white; border-radius: 3px; }
        .evidence { background: #2c3e50; color: white; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
        .recommendation { background: #e8f5e8; border-left: 4px solid #27ae60; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Web Application Vulnerability Scan Report</h1>
            <p>Generated on {{ scan_result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>

        <div class="section">
            <h2>Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{{ scan_result.target_url }}</div>
                    <div class="stat-label">Target URL</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ "%.2f"|format(scan_result.scan_duration) }}s</div>
                    <div class="stat-label">Scan Duration</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ len(scan_result.discovered_pages) }}</div>
                    <div class="stat-label">Pages Discovered</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ len(scan_result.vulnerabilities) }}</div>
                    <div class="stat-label">Vulnerabilities Found</div>
                </div>
            </div>
        </div>

        {% if scan_result.software_stack %}
        <div class="section">
            <h2>🖥️ Software Stack Detected</h2>
            <div class="url-list">
                {% for tech, info in scan_result.software_stack.items() %}
                <div><strong>{{ tech }}:</strong> {{ info }}</div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if scan_result.discovered_pages %}
        <div class="section">
            <h2>Discovered Pages</h2>
            <div class="url-list">
                {% for page in scan_result.discovered_pages %}
                <div><a href="{{ page }}" target="_blank">{{ page }}</a></div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if scan_result.discovered_forms %}
        <div class="section">
            <h2>📝 Discovered Forms</h2>
            {% for form in scan_result.discovered_forms %}
            <div class="form-details">
                <h3>Form on {{ form.page_url }}</h3>
                <p><strong>Action:</strong> {{ form.action or 'Same page' }} | <strong>Method:</strong> {{ form.method }}</p>
                <p><strong>Input Fields:</strong></p>
                {% for inp in form.inputs %}
                <div class="input-field">
                    <strong>{{ inp.type }}:</strong> {{ inp.name }} {% if inp.id %}(ID: {{ inp.id }}){% endif %}
                    {% if inp.required %}<span style="color: #e74c3c;">*Required</span>{% endif %}
                </div>
                {% endfor %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if scan_result.vulnerabilities %}
        <div class="section">
            <h2>Vulnerability Findings</h2>
            {% for vuln in scan_result.vulnerabilities %}
            <div class="vulnerability {{ vuln.risk_level.value.lower() }}">
                <h3>{{ vuln.name }}</h3>
                <span class="risk-badge risk-{{ vuln.risk_level.value.lower() }}">{{ vuln.risk_level.value }}</span>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                <p><strong>Location:</strong> <a href="{{ vuln.location }}" target="_blank">{{ vuln.location }}</a></p>
                {% if vuln.evidence %}
                <div class="evidence">
                    <strong>Evidence:</strong> {{ vuln.evidence }}
                </div>
                {% endif %}
                {% if vuln.recommendation %}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                </div>
                {% endif %}
                {% if vuln.cwe_id %}
                <p><strong>CWE ID:</strong> {{ vuln.cwe_id }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="section">
            <h2>✅ No Vulnerabilities Detected</h2>
            <p>Congratulations! No security vulnerabilities were found during this scan.</p>
        </div>
        {% endif %}

        <div class="footer">
            <p>Report generated by Web Vulnerability Scanner</p>
            <p>This is a non-intrusive security assessment tool</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(scan_result=scan_result)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {report_path}")
        return report_path
    
    def _generate_markdown_report(self, scan_result: ScanResult, filename: str) -> str:
        """Generate Markdown report"""
        report_path = os.path.join(self.reports_dir, f"{filename}.md")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# Web Application Vulnerability Scan Report\n\n")
            f.write(f"**Target URL:** {scan_result.target_url}\n")
            f.write(f"**Scan Timestamp:** {scan_result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Scan Duration:** {scan_result.scan_duration:.2f} seconds\n\n")
            
            f.write("## Scan Summary\n\n")
            f.write(f"- **Pages Discovered:** {len(scan_result.discovered_pages)}\n")
            f.write(f"- **Forms Found:** {len(scan_result.discovered_forms)}\n")
            f.write(f"- **Vulnerabilities:** {len(scan_result.vulnerabilities)}\n\n")
            
            if scan_result.software_stack:
                f.write("## 🖥️ Software Stack\n\n")
                for tech, info in scan_result.software_stack.items():
                    f.write(f"- **{tech}:** {info}\n")
                f.write("\n")
            
            if scan_result.discovered_pages:
                f.write("## Discovered Pages\n\n")
                for page in scan_result.discovered_pages:
                    f.write(f"- [{page}]({page})\n")
                f.write("\n")
            
            if scan_result.discovered_forms:
                f.write("## 📝 Discovered Forms\n\n")
                for form in scan_result.discovered_forms:
                    f.write(f"### Form on {form['page_url']}\n")
                    f.write(f"- **Action:** {form['action'] or 'Same page'}\n")
                    f.write(f"- **Method:** {form['method']}\n")
                    f.write(f"- **Inputs:** {len(form['inputs'])}\n")
                    for inp in form['inputs']:
                        f.write(f"  - `{inp['type']}`: {inp['name']}")
                        if inp['id']:
                            f.write(f" (ID: {inp['id']})")
                        if inp['required']:
                            f.write(" **Required**")
                        f.write("\n")
                    f.write("\n")
            
            if scan_result.vulnerabilities:
                f.write("## Vulnerability Findings\n\n")
                
                # Group by risk level
                risk_groups = {}
                for vuln in scan_result.vulnerabilities:
                    risk = vuln.risk_level.value
                    if risk not in risk_groups:
                        risk_groups[risk] = []
                    risk_groups[risk].append(vuln)
                
                risk_order = ['Critical', 'High', 'Medium', 'Low', 'Information']
                
                for risk_level in risk_order:
                    if risk_level in risk_groups:
                        f.write(f"### {risk_level} Risk Vulnerabilities\n\n")
                        
                        for vuln in risk_groups[risk_level]:
                            f.write(f"#### {vuln.name}\n\n")
                            f.write(f"**Risk Level:** {vuln.risk_level.value}\n\n")
                            f.write(f"**Description:** {vuln.description}\n\n")
                            f.write(f"**Location:** [{vuln.location}]({vuln.location})\n\n")
                            
                            if vuln.evidence:
                                f.write(f"**Evidence:**\n```\n{vuln.evidence}\n```\n\n")
                            
                            if vuln.recommendation:
                                f.write(f"**Recommendation:** {vuln.recommendation}\n\n")
                            
                            if vuln.cwe_id:
                                f.write(f"**CWE ID:** {vuln.cwe_id}\n\n")
                            
                            f.write("---\n\n")
            else:
                f.write("## ✅ No Vulnerabilities Detected\n\n")
                f.write("Congratulations! No security vulnerabilities were found during this scan.\n\n")
            
            f.write("---\n\n")
            f.write("*Report generated by Web Vulnerability Scanner*\n")
        
        print(f"Markdown report generated: {report_path}")
        return report_path
    
    def _generate_json_report(self, scan_result: ScanResult, filename: str) -> str:
        """Generate JSON report"""
        report_path = os.path.join(self.reports_dir, f"{filename}.json")
        
        # Convert scan result to JSON-serializable format
        report_data = {
            "scan_info": {
                "target_url": scan_result.target_url,
                "scan_timestamp": scan_result.scan_timestamp.isoformat(),
                "scan_duration": scan_result.scan_duration,
                "total_pages": len(scan_result.discovered_pages),
                "total_forms": len(scan_result.discovered_forms),
                "total_vulnerabilities": len(scan_result.vulnerabilities)
            },
            "software_stack": scan_result.software_stack,
            "discovered_pages": list(scan_result.discovered_pages),
            "discovered_forms": scan_result.discovered_forms,
            "security_headers": scan_result.security_headers,
            "cookies": scan_result.cookies,
            "vulnerabilities": [
                {
                    "name": vuln.name,
                    "description": vuln.description,
                    "risk_level": vuln.risk_level.value,
                    "location": vuln.location,
                    "evidence": vuln.evidence,
                    "recommendation": vuln.recommendation,
                    "cwe_id": vuln.cwe_id
                }
                for vuln in scan_result.vulnerabilities
            ]
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"JSON report generated: {report_path}")
        return report_path

def main():
    """Test the report generator"""
    # This is just for testing - in real usage, it's called from scanner.py
    print("Report Generator - This module is designed to be imported by scanner.py")
    print("To generate a report, run: python scanner.py <target_url> --output <format>")

if __name__ == "__main__":
    main()
