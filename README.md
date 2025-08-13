# 🔒 Web Application Vulnerability Scanner

A comprehensive, non-intrusive web application vulnerability assessment tool designed for security professionals, developers, and ethical hackers. This tool performs passive reconnaissance and vulnerability checks against web applications while generating detailed, structured reports.

## 🎯 Features

### 1. Target Input & URL Parsing
- Accepts URLs/domains from users
- Validates and parses target endpoints
- Supports both HTTP and HTTPS protocols
- **NEW**: Interactive CLI interface with `run_scanner.py`

### 2. Passive Reconnaissance & Discovery
- **Website Crawling**: Discovers pages and forms through link analysis
- **Hidden Path Detection**: Identifies common sensitive directories and files
- **Form Analysis**: Extracts and analyzes HTML forms for security assessment
- **Token Detection**: Identifies hidden fields and potential security tokens
- **Session Management**: Handles authentication and CSRF tokens

### 3. Vulnerability Checks (Non-Intrusive Only)
- **Security Headers**: Checks for missing or insecure security headers
  - CSP (Content Security Policy)
  - HSTS (HTTP Strict Transport Security)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy

- **Cookie Security**: Analyzes cookie configurations for security issues
  - Missing Secure flag
  - Missing HttpOnly flag
  - Domain and path restrictions

- **OWASP Top 10 Coverage**: Comprehensive vulnerability testing
  - **A01:2021 - Broken Access Control**: Tests for unauthorized access
  - **A02:2021 - Cryptographic Failures**: Checks for sensitive data exposure
  - **A03:2021 - Injection**: SQL, Command, and Path Traversal injection
  - **A04:2021 - Insecure Design**: Identifies design flaws
  - **A05:2021 - Security Misconfiguration**: Headers, cookies, and server configs
  - **A06:2021 - Vulnerable Components**: Software stack identification
  - **A07:2021 - Authentication Failures**: Session management and logout testing
  - **A08:2021 - Software and Data Integrity Failures**: File upload vulnerabilities
  - **A09:2021 - Security Logging Failures**: Audit trail analysis
  - **A10:2021 - SSRF**: Server-side request forgery detection

- **Advanced Input Validation**: Tests forms for potential vulnerabilities
  - **Reflected XSS detection** (50+ payloads including advanced vectors)
  - **SQL injection indicators** (30+ payloads with error-based detection)
  - **Command injection testing** (Windows/Linux payloads)
  - **Path traversal detection** (directory traversal testing)
  - **File upload vulnerability testing** (dangerous file extensions)
  - **CSRF vulnerability detection** (missing tokens on sensitive forms)
  - **Unsanitized parameter handling**

- **Software Stack Identification**: Detects underlying technologies
  - Web servers (Apache, Nginx, IIS)
  - Programming languages (PHP, Python, Java, .NET)
  - Frameworks (WordPress, Drupal, Django, Flask)

- **Directory Enumeration**: Checks for open directory listings

### 4. Enhanced Features
- **Authentication Support**: Handles login forms with CSRF token bypass
- **Smart False Positive Reduction**: Filters static content and documentation pages
- **DVWA-Specific Testing**: Targets known vulnerable pages (SQLi, XSS, File Upload)
- **Enhanced Payload Library**: Comprehensive collection of attack vectors
- **Intelligent Crawling**: Skips irrelevant pages to focus on vulnerable content

### 5. Comprehensive Reporting
- **Multiple Formats**: TXT, HTML, Markdown, and JSON
- **Structured Output**: Organized by vulnerability type and risk level
- **Risk Assessment**: Categorized findings (Critical, High, Medium, Low, Information)
- **Evidence Collection**: Provides proof of vulnerabilities found with payloads
- **Recommendations**: Actionable security improvement suggestions
- **Scan Statistics**: Pages discovered, forms tested, vulnerabilities found

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Setup

#### Option 1: Clone from GitHub (Recommended)
```bash
git clone https://github.com/YOUR_USERNAME/web-vulnerability-scanner.git
cd web-vulnerability-scanner
pip install -r requirements.txt
```

#### Option 2: Download ZIP
1. Download the project ZIP from GitHub
2. Extract the files
3. Navigate to the project directory
4. Install required dependencies:

```bash
pip install -r requirements.txt
```

## 📖 Usage

### Interactive Mode (Recommended)
```bash
python run_scanner.py
```
This launches an interactive interface where you can:
- Enter target URL
- Configure scan options
- Provide authentication credentials
- Choose output format

### Command Line Mode
```bash
python run_scanner.py <target_url> [options]
```

### Direct Scanner Usage
```bash
python scanner.py <target_url>
```

### Advanced Usage
```bash
python scanner.py <target_url> [options]

Options:
  --depth INT        Maximum crawl depth (default: 3)
  --timeout INT      Request timeout in seconds (default: 30)
  --output FORMAT    Output format: txt, html, md, json (default: txt)
  --username USER    Username for authentication
  --password PASS    Password for authentication
```

### Examples

#### Interactive Scan
```bash
python run_scanner.py
# Follow the prompts to configure your scan
```

#### Simple Scan
```bash
python scanner.py https://example.com
```

#### Authenticated Scan
```bash
python run_scanner.py https://example.com --username admin --password password
```

#### Deep Scan with Custom Output
```bash
python scanner.py https://example.com --depth 5 --output html
```

#### Quick Scan with JSON Output
```bash
python scanner.py https://example.com --depth 2 --output json
```

## 📊 Output Formats

### 1. Text Report (.txt)
- Human-readable plain text format
- Suitable for terminal viewing and basic documentation
- Includes all scan findings with clear formatting
- **Enhanced**: Shows payload evidence and vulnerability details

### 2. HTML Report (.html)
- Professional, styled web report
- Interactive elements and visual risk indicators
- Perfect for sharing with stakeholders and clients
- Responsive design for various screen sizes

### 3. Markdown Report (.md)
- Structured markdown format
- Easy to convert to other formats
- Suitable for documentation systems and wikis
- GitHub-compatible formatting

### 4. JSON Report (.json)
- Machine-readable structured data
- Perfect for integration with other tools
- API-friendly format
- Easy to parse and analyze programmatically

## 🔍 Scan Process

### Phase 1: Target Validation
- URL format validation
- Protocol verification
- Domain resolution check

### Phase 2: Authentication (if provided)
- Login form detection
- CSRF token handling
- Session management
- Cookie persistence

### Phase 3: Passive Reconnaissance
- Website crawling (configurable depth)
- Link discovery and analysis
- Form extraction and analysis
- Hidden path enumeration
- Smart content filtering

### Phase 4: Vulnerability Assessment
- Security header analysis
- Cookie security review
- OWASP Top 10 vulnerability testing
- Input validation testing with enhanced payloads
- Technology stack identification
- Directory listing checks
- DVWA-specific vulnerability testing

### Phase 5: Report Generation
- Data compilation and analysis
- Risk level categorization
- Evidence collection with payloads
- Recommendation generation
- Multi-format output creation

## ⚠️ Risk Levels

### Critical
- SQL injection vulnerabilities
- Command injection vulnerabilities
- Critical security misconfigurations
- Immediate security threats

### High
- Reflected XSS vulnerabilities
- File upload vulnerabilities
- Missing critical security headers
- Insecure cookie configurations
- Path traversal vulnerabilities

### Medium
- Missing security headers
- Open directory listings
- Potentially sensitive path access
- CSRF vulnerabilities
- SSRF vulnerabilities

### Low
- Information disclosure
- Minor configuration issues
- Best practice violations

### Information
- Hidden fields detected
- Technology stack information
- General security observations

## 🛡️ Ethical Considerations

### Important Disclaimers
- **This tool is for authorized security testing only**
- **Always obtain proper permission before scanning any website**
- **Respect robots.txt and rate limiting**
- **Do not use for malicious purposes**

### Responsible Usage
- Only scan websites you own or have explicit permission to test
- Respect website terms of service
- Avoid overwhelming servers with excessive requests
- Report vulnerabilities responsibly to website owners

### Legal Compliance
- Ensure compliance with local laws and regulations
- Understand the legal implications of security testing
- Maintain proper documentation of authorized testing

## 🔧 Configuration

### Customization Options
- **Crawl Depth**: Control how deep the scanner explores
- **Timeout Settings**: Adjust request timeouts for different network conditions
- **Output Formats**: Choose the most suitable report format
- **User Agent**: Customize the scanner's user agent string
- **Authentication**: Support for login credentials and session management

### Advanced Features
- Session management for authenticated scans
- Custom vulnerability patterns
- Extensible plugin architecture
- Integration capabilities with other security tools
- Smart false positive reduction
- Enhanced payload libraries

## 📁 Project Structure

```
Vulnerability Scanner/
├── scanner.py              # Main scanner implementation
├── run_scanner.py          # Interactive user interface
├── config.py               # Configuration and payloads
├── report_generator.py     # Report generation engine
├── requirements.txt        # Python dependencies
├── README.md              # This documentation
└── reports/               # Generated reports directory
    ├── vuln_scan_*.txt    # Text reports
    ├── vuln_scan_*.html   # HTML reports
    ├── vuln_scan_*.md     # Markdown reports
    └── vuln_scan_*.json   # JSON reports
```

## 🐛 Troubleshooting

### Common Issues

#### Connection Errors
- Check internet connectivity
- Verify target URL accessibility
- Adjust timeout settings
- Check firewall/proxy settings

#### Authentication Issues
- Verify credentials are correct
- Check if target uses CSRF protection
- Ensure proper session handling
- Try different authentication methods

#### Import Errors
- Ensure all dependencies are installed
- Verify Python version compatibility
- Check virtual environment activation

#### Permission Errors
- Ensure write permissions for reports directory
- Check file system permissions
- Verify user account privileges

### Performance Optimization
- Reduce crawl depth for large websites
- Increase timeout for slow servers
- Use appropriate output format for your needs
- Consider running during off-peak hours

## 🤝 Contributing

### Development Guidelines
- Follow Python PEP 8 style guidelines
- Add comprehensive error handling
- Include proper documentation
- Write unit tests for new features

### Feature Requests
- Submit detailed feature descriptions
- Include use case scenarios
- Provide examples when possible

### Bug Reports
- Include detailed error messages
- Provide reproduction steps
- Specify environment details
- Attach relevant log files

## 📚 Additional Resources

### Security Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

### Learning Resources
- Web application security fundamentals
- HTTP security headers
- Common web vulnerabilities
- Ethical hacking practices

### Related Tools
- Burp Suite
- OWASP ZAP
- Nikto
- Nmap

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and contribute to the project.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Disclaimer**: This project is provided for educational and authorized security testing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## ⚡ Quick Start Example

```bash
# Install dependencies
pip install -r requirements.txt

# Run interactive scan (Recommended)
python run_scanner.py

# Or run a basic scan
python scanner.py https://example.com

# Run a comprehensive scan with HTML report
python scanner.py https://example.com --depth 5 --output html

# Check the generated reports
ls reports/
```

## 🎉 Success Stories

This vulnerability scanner has been successfully used for:
- Security assessments of corporate websites
- Educational security training
- Penetration testing exercises
- Security research and development
- Compliance auditing
- **DVWA vulnerability testing and demonstration**
- **OWASP Top 10 vulnerability assessment**

## 🔥 Recent Enhancements

### Version 2.0 Features
- **Complete OWASP Top 10 Coverage**: All 10 vulnerability categories
- **Enhanced Authentication**: CSRF token handling and session management
- **Advanced Payload Library**: 50+ XSS payloads, 30+ SQL injection payloads
- **Smart False Positive Reduction**: Filters static content and documentation
- **DVWA-Specific Testing**: Targets known vulnerable pages
- **Interactive CLI Interface**: User-friendly `run_scanner.py`
- **Comprehensive Form Testing**: Tests all discovered forms for vulnerabilities
- **Enhanced Reporting**: Detailed evidence with payloads and responses

---

**Remember: Security is everyone's responsibility. Use this tool responsibly and ethically to make the web a safer place for everyone.**
