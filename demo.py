#!/usr/bin/env python3
"""
Demo module for Web Vulnerability Scanner
Provides a safe, quick demo scan against a public example site.
"""

from datetime import datetime

def demo_scan() -> bool:
    """Run a short demo scan and generate a TXT report."""
    try:
        from scanner import WebVulnerabilityScanner
        from report_generator import ReportGenerator
    except ImportError as e:
        print(f"Import error: {e}")
        print("Please install dependencies: pip install -r requirements.txt")
        return False

    target_url = "https://example.com"
    max_depth = 1
    timeout = 10
    output_format = "txt"

    print("Starting demo scan...")
    print(f"   Target: {target_url}")
    print(f"   Depth: {max_depth}")
    print(f"   Timeout: {timeout}s")
    print(f"   Output: {output_format}")
    print()

    try:
        scanner = WebVulnerabilityScanner(
            target_url=target_url,
            max_depth=max_depth,
            timeout=timeout,
            cookies={},
            auth_credentials={}
        )

        start_time = datetime.now()
        results = scanner.start_scan()
        duration = (datetime.now() - start_time).total_seconds()

        print(f"Demo scan completed in {duration:.2f} seconds")
        print("Generating demo report...")

        rg = ReportGenerator()
        path = rg.generate_report(results, output_format)
        print(f"Report written to: {path}")
        return True
    
    except Exception as e:
        print(f"Demo scan failed: {e}")
        return False

if __name__ == "__main__":
    demo_scan()


