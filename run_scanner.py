#!/usr/bin/env python3
"""
Launcher script for Web Vulnerability Scanner
Provides a user-friendly interface for running scans
"""

import sys
import os
import argparse
from datetime import datetime

def _parse_cookies_str(raw: str) -> dict:
    """Parse a cookie string like 'a=1,b=2' or 'a=1; b=2' into a dict."""
    if not raw:
        return {}
    cookies = {}
    for pair in raw.replace(';', ',').split(','):
        pair = pair.strip()
        if not pair:
            continue
        if '=' in pair:
            name, value = pair.split('=', 1)
            cookies[name.strip()] = value.strip()
    return cookies

def print_banner():
    """Print the scanner banner"""
    print("=" * 60)
    print("   WEB APPLICATION VULNERABILITY SCANNER")
    print("   Module 7: Technical Capstone Project")
    print("   Non-Intrusive Security Assessment Tool")
    print("=" * 62)
    print()

def print_ethical_warning():
    """Print ethical usage warning"""
    print("ETHICAL USAGE WARNING:")
    print("   • Only scan websites you own or have explicit permission to test")
    print("   • This tool is for authorized security testing only")
    print("   • Respect website terms of service and rate limits")
    print("   • Report vulnerabilities responsibly to website owners")
    print("   • Ensure compliance with local laws and regulations")
    print()

def get_user_input():
    """Get target URL from user input"""
    while True:
        url = input("Enter target URL (e.g., https://example.com): ").strip()
        
        if not url:
            print("❌ URL cannot be empty. Please try again.")
            continue
            
        # Basic URL validation
        if not (url.startswith('http://') or url.startswith('https://')):
            print("❌ URL must start with http:// or https://")
            print("💡 Adding https:// automatically...")
            url = 'https://' + url
            
        # Confirm with user
        print(f"Target URL: {url}")
        confirm = input("✅ Is this correct? (y/n): ").strip().lower()
        
        if confirm in ['y', 'yes']:
            return url
        elif confirm in ['n', 'no']:
            continue
        else:
            print("❌ Please enter 'y' or 'n'")

def get_scan_options():
    """Get scan options from user"""
    print("\n⚙️  Scan Configuration:")
    
    # Crawl depth
    while True:
        try:
            depth = input("Crawl depth (1-5, default 3): ").strip()
            if not depth:
                depth = 3
                break
            depth = int(depth)
            if 1 <= depth <= 5:
                break
            else:
                print("❌ Depth must be between 1 and 5")
        except ValueError:
            print("❌ Please enter a valid number")
    
    # Timeout
    while True:
        try:
            timeout = input("⏱️  Request timeout in seconds (10-120, default 30): ").strip()
            if not timeout:
                timeout = 30
                break
            timeout = int(timeout)
            if 10 <= timeout <= 120:
                break
            else:
                print("❌ Timeout must be between 10 and 120 seconds")
        except ValueError:
            print("❌ Please enter a valid number")
    
    # Output format
            print("\nOutput Format Options:")
    print("   1. Text (.txt) - Human readable")
    print("   2. HTML (.html) - Professional web report")
    print("   3. Markdown (.md) - Documentation friendly")
    print("   4. JSON (.json) - Machine readable")
    print("   5. All formats")
    
    while True:
        choice = input("   Choose format (1-5, default 1): ").strip()
        if not choice:
            choice = '1'
        
        format_map = {
            '1': 'txt',
            '2': 'html', 
            '3': 'md',
            '4': 'json',
            '5': 'all'
        }
        
        if choice in format_map:
            output_format = format_map[choice]
            break
        else:
            print("❌ Please enter a number between 1 and 5")
    
    return depth, timeout, output_format

def get_auth_credentials():
    """Get authentication credentials from user"""
    print("\nAuthentication Configuration:")
    print("   • Leave blank to skip authentication")
    print("   • Enter credentials if the target requires login")
    print()
    
    username = input("Username (optional): ").strip()
    password = input("Password (optional): ").strip()
    
    if username and password:
        print("Authentication credentials provided")
        return {'username': username, 'password': password}
    else:
        print("No authentication credentials - will attempt unauthenticated scan")
        return {}

def run_scan(target_url, depth, timeout, output_format, auth_credentials=None, cookies=None):
    """Run the vulnerability scan"""
    print(f"\nStarting vulnerability scan...")
    print(f"   Target: {target_url}")
    print(f"   Depth: {depth}")
    print(f"   Timeout: {timeout}s")
    print(f"   Output: {output_format}")
    if auth_credentials:
        print(f"   Authentication: {auth_credentials.get('username', 'Unknown')}")
    else:
        print(f"   Authentication: None")
    if cookies:
        print(f"   Cookies: {len(cookies)} provided")
    else:
        print("   Cookies: None")
    print()
    
    try:
        # Import scanner (this will fail if dependencies aren't installed)
        from scanner import WebVulnerabilityScanner
        from report_generator import ReportGenerator
        
        # Initialize scanner
        scanner = WebVulnerabilityScanner(
            target_url=target_url,
            max_depth=depth,
            timeout=timeout,
            cookies=cookies,
            auth_credentials=auth_credentials
        )
        
        # Run scan
        print("Scanning in progress... This may take several minutes.")
        print("   Please wait...")
        
        start_time = datetime.now()
        results = scanner.start_scan()
        end_time = datetime.now()
        
        scan_duration = (end_time - start_time).total_seconds()
        
        print(f"\nScan completed in {scan_duration:.2f} seconds!")
        print()
        
        # Display results summary
        print("Scan Results Summary:")
        print(f"   • Pages discovered: {len(results.discovered_pages)}")
        print(f"   • Forms found: {len(results.discovered_forms)}")
        print(f"   • Vulnerabilities detected: {len(results.vulnerabilities)}")
        print()
        
        # Display vulnerability summary by risk level
        if results.vulnerabilities:
            risk_counts = {}
            for vuln in results.vulnerabilities:
                risk = vuln.risk_level.value
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            print("Vulnerability Summary:")
            risk_order = ['Critical', 'High', 'Medium', 'Low', 'Information']
            for risk in risk_order:
                if risk in risk_counts:
                    count = risk_counts[risk]
                    print(f"   {risk}: {count}")
            print()
        
        # Generate reports
        print("Generating reports...")
        report_generator = ReportGenerator()
        
        if output_format == 'all':
            formats = ['txt', 'html', 'md', 'json']
        else:
            formats = [output_format]
        
        generated_reports = []
        for fmt in formats:
            try:
                report_path = report_generator.generate_report(results, fmt)
                generated_reports.append((fmt, report_path))
                print(f"   {fmt.upper()} report generated")
            except Exception as e:
                print(f"   Failed to generate {fmt.upper()} report: {str(e)}")
        
        print()
        print("Reports generated successfully!")
        print("   Location: reports/ directory")
        for fmt, path in generated_reports:
            filename = os.path.basename(path)
            print(f"   • {fmt.upper()}: {filename}")
        
        # Open HTML report if available
        html_report = next((path for fmt, path in generated_reports if fmt == 'html'), None)
        if html_report:
            print()
            open_html = input("🌐 Open HTML report in browser? (y/n): ").strip().lower()
            if open_html in ['y', 'yes']:
                try:
                    import webbrowser
                    webbrowser.open(f"file://{os.path.abspath(html_report)}")
                    print("   ✅ HTML report opened in browser")
                except Exception as e:
                    print(f"   ❌ Failed to open browser: {str(e)}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        print("💡 Please install required dependencies:")
        print("   pip install -r requirements.txt")
        return False
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        print("💡 Check the error message above and try again")
        return False

def main():
    """Main launcher function"""
    print_banner()
    print_ethical_warning()
    
    # Check if running with command line arguments
    if len(sys.argv) > 1:
        # Command line mode
        parser = argparse.ArgumentParser(description='Web Application Vulnerability Scanner')
        parser.add_argument('url', help='Target URL to scan')
        parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
        parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
        parser.add_argument('--output', choices=['txt', 'html', 'md', 'json', 'all'], default='txt',
                          help='Output format (default: txt)')
        parser.add_argument('--username', help='Username for authentication')
        parser.add_argument('--password', help='Password for authentication')
        parser.add_argument('--cookies', help='Cookies as name=value pairs separated by comma or semicolon')
        
        args = parser.parse_args()
        
        print(f"Target URL: {args.url}")
        print(f"Depth: {args.depth}, Timeout: {args.timeout}s, Output: {args.output}")
        if args.username and args.password:
            print(f"Authentication: {args.username}")
        else:
            print(f"Authentication: None")
        if args.cookies:
            print(f"Cookies: provided")
        else:
            print("Cookies: None")
        print()
        
        # Prepare auth credentials
        auth_credentials = {}
        if args.username and args.password:
            auth_credentials = {'username': args.username, 'password': args.password}
        
        cookies = _parse_cookies_str(args.cookies) if args.cookies else {}
        success = run_scan(args.url, args.depth, args.timeout, args.output, auth_credentials, cookies)
        sys.exit(0 if success else 1)
    
    # Interactive mode
    try:
        while True:
            print("Choose an option:")
            print("1. Run Vulnerability Scan")
            print("2. Run Demo Scan (Safe)")
            print("3. Show Help")
            print("4. Exit")
            print()
            
            choice = input("Enter your choice (1-4): ").strip()
            
            if choice == '1':
                print()
                target_url = get_user_input()
                depth, timeout, output_format = get_scan_options()
                auth_credentials = get_auth_credentials()
                # Ask for cookies interactively
                print("\nCookie Configuration (optional)")
                print("   Enter cookies as name=value pairs separated by commas or semicolons")
                raw_cookies = input("Cookies (press Enter to skip): ").strip()
                cookies = _parse_cookies_str(raw_cookies)
                
                print()
                print("Ready to start scan!")
                confirm = input("   Press Enter to continue or 'q' to quit: ").strip()
                if confirm.lower() == 'q':
                    print("❌ Scan cancelled")
                    continue
                
                success = run_scan(target_url, depth, timeout, output_format, auth_credentials, cookies)
                if success:
                    print("\nScan completed successfully!")
                
                input("\nPress Enter to continue...")
                print()
                
            elif choice == '2':
                print()
                print("Starting demo scan...")
                try:
                    from demo import demo_scan
                    demo_scan()
                except ImportError:
                    print("❌ Demo module not found")
                except Exception as e:
                    print(f"❌ Demo failed: {str(e)}")
                
                input("\nPress Enter to continue...")
                print()
                
            elif choice == '3':
                print()
                print("Help Information:")
                print("   • This tool performs non-intrusive vulnerability assessments")
                print("   • It crawls websites and checks for common security issues")
                print("   • Reports are generated in multiple formats")
                print("   • Always obtain permission before scanning websites")
                print()
                print("💡 For command line usage:")
                print("   python run_scanner.py <url> [options]")
                print()
                print("See README.md for detailed documentation")
                print()
                
                input("Press Enter to continue...")
                print()
                
            elif choice == '4':
                print("👋 Goodbye! Stay secure!")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")
                print()
                
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Stay secure!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
