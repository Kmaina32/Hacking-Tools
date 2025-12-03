"""
Web Security Injection Tester
=============================
Educational tool for understanding SQL Injection and XSS vulnerabilities.
Demonstrates common injection patterns and detection methods.

DISCLAIMER: Only use on systems you own or have explicit permission to test.
"""

import re
from typing import List, Tuple


class SQLInjectionTester:
    """Test for SQL Injection vulnerabilities."""
    
    # Common SQL injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1/*",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "admin'--",
        "' OR 'a'='a",
    ]
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"(\bOR\b.*=.*)",
        r"(\bUNION\b)",
        r"(DROP|DELETE|INSERT|UPDATE)\s+\w+",
        r"(-{2}|/\*|\*/)",
        r"(\b(AND|OR)\b\s+\d+\s*=\s*\d+)",
    ]
    
    @staticmethod
    def check_vulnerability(user_input: str) -> Tuple[bool, List[str]]:
        """Check if input contains SQL injection patterns."""
        detected_patterns = []
        
        for pattern in SQLInjectionTester.SQL_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        is_vulnerable = len(detected_patterns) > 0
        return is_vulnerable, detected_patterns
    
    @staticmethod
    def sanitize_input(user_input: str) -> str:
        """Remove potentially dangerous SQL characters."""
        # Remove single quotes
        sanitized = user_input.replace("'", "")
        # Remove SQL comments
        sanitized = re.sub(r"(-{2}|/\*|\*/)", "", sanitized)
        # Remove multiple spaces
        sanitized = re.sub(r"\s+", " ", sanitized)
        return sanitized
    
    @staticmethod
    def escape_input(user_input: str) -> str:
        """Properly escape user input for SQL."""
        # Double single quotes for SQL escaping
        return user_input.replace("'", "''")
    
    @staticmethod
    def generate_test_report(user_input: str) -> dict:
        """Generate a detailed vulnerability report."""
        is_vulnerable, patterns = SQLInjectionTester.check_vulnerability(user_input)
        
        return {
            'input': user_input,
            'vulnerable': is_vulnerable,
            'detected_patterns': patterns,
            'sanitized': SQLInjectionTester.sanitize_input(user_input),
            'escaped': SQLInjectionTester.escape_input(user_input),
        }


class XSSVulnerabilityTester:
    """Test for Cross-Site Scripting (XSS) vulnerabilities."""
    
    # Common XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"on\w+\s*=",
        r"javascript:",
        r"<iframe",
        r"<img[^>]*onerror",
        r"<svg[^>]*onload",
    ]
    
    @staticmethod
    def check_vulnerability(user_input: str) -> Tuple[bool, List[str]]:
        """Check if input contains XSS patterns."""
        detected_patterns = []
        
        for pattern in XSSVulnerabilityTester.XSS_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        is_vulnerable = len(detected_patterns) > 0
        return is_vulnerable, detected_patterns
    
    @staticmethod
    def sanitize_html(user_input: str) -> str:
        """Remove HTML and dangerous characters."""
        # Remove HTML tags
        sanitized = re.sub(r"<[^>]+>", "", user_input)
        # Escape special HTML characters
        sanitized = sanitized.replace("&", "&amp;")
        sanitized = sanitized.replace("<", "&lt;")
        sanitized = sanitized.replace(">", "&gt;")
        sanitized = sanitized.replace('"', "&quot;")
        sanitized = sanitized.replace("'", "&#x27;")
        return sanitized
    
    @staticmethod
    def encode_html_entities(user_input: str) -> str:
        """Encode input as HTML entities."""
        entities = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
        }
        return ''.join(entities.get(c, c) for c in user_input)
    
    @staticmethod
    def generate_test_report(user_input: str) -> dict:
        """Generate a detailed vulnerability report."""
        is_vulnerable, patterns = XSSVulnerabilityTester.check_vulnerability(user_input)
        
        return {
            'input': user_input,
            'vulnerable': is_vulnerable,
            'detected_patterns': patterns,
            'sanitized': XSSVulnerabilityTester.sanitize_html(user_input),
            'html_encoded': XSSVulnerabilityTester.encode_html_entities(user_input),
        }


def main():
    """Interactive demonstration."""
    print("="*60)
    print("Web Security Injection Tester - Educational Tool")
    print("="*60)
    
    # SQL Injection Testing
    print("\n[*] SQL Injection Testing:")
    print("-" * 60)
    
    sql_test_cases = [
        "john",
        "' OR '1'='1",
        "'; DROP TABLE users--",
    ]
    
    for test_input in sql_test_cases:
        report = SQLInjectionTester.generate_test_report(test_input)
        print(f"\n  Input: {test_input}")
        print(f"  Vulnerable: {report['vulnerable']}")
        if report['detected_patterns']:
            print(f"  Detected Patterns: {report['detected_patterns']}")
        print(f"  Sanitized: {report['sanitized']}")
        print(f"  Escaped: {report['escaped']}")
    
    # XSS Testing
    print("\n\n[*] XSS Vulnerability Testing:")
    print("-" * 60)
    
    xss_test_cases = [
        "Hello World",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
    ]
    
    for test_input in xss_test_cases:
        report = XSSVulnerabilityTester.generate_test_report(test_input)
        print(f"\n  Input: {test_input}")
        print(f"  Vulnerable: {report['vulnerable']}")
        if report['detected_patterns']:
            print(f"  Detected Patterns: {report['detected_patterns']}")
        print(f"  Sanitized: {report['sanitized']}")
        print(f"  HTML Encoded: {report['html_encoded']}")


if __name__ == '__main__':
    main()
