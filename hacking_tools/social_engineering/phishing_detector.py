"""
Phishing Detector - Social Engineering Awareness Tool
=====================================================
Educational tool for understanding phishing techniques and detection.
Helps identify suspicious emails and URLs commonly used in phishing attacks.
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class PhishingDetector:
    """Detect phishing indicators in emails and URLs."""
    
    # Suspicious keywords
    PHISHING_KEYWORDS = [
        'verify', 'confirm', 'urgent', 'immediate action', 'click here',
        'update payment', 'account suspended', 'unusual activity',
        'confirm identity', 'reset password', 'validate', 'required',
        'act now', 'do not reply', 'limited time', 'security alert',
    ]
    
    # Common phishing domains/misspellings
    SUSPICIOUS_DOMAINS = [
        'paypa1.com',  # l instead of i
        'amaz0n.com',  # 0 instead of o
        'appl.com',
        'goog1e.com',
        'micr0soft.com',
    ]
    
    # Legitimate company domains
    LEGITIMATE_DOMAINS = [
        'paypal.com', 'amazon.com', 'apple.com', 'google.com',
        'microsoft.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    ]
    
    @staticmethod
    def analyze_email(sender: str, subject: str, body: str) -> Dict:
        """Analyze email for phishing indicators."""
        risk_score = 0
        red_flags = []
        
        # Check sender domain legitimacy
        sender_domain = sender.split('@')[1] if '@' in sender else ''
        if sender_domain in PhishingDetector.SUSPICIOUS_DOMAINS:
            risk_score += 3
            red_flags.append(f"Suspicious domain: {sender_domain}")
        
        # Check for generic greetings
        if re.search(r'\b(dear user|dear customer|dear valued customer)\b', body, re.IGNORECASE):
            risk_score += 1
            red_flags.append("Generic greeting (not personalized)")
        
        # Check for urgency language
        urgency_count = sum(1 for keyword in PhishingDetector.PHISHING_KEYWORDS 
                           if keyword in body.lower())
        if urgency_count >= 3:
            risk_score += 2
            red_flags.append(f"High urgency language ({urgency_count} keywords found)")
        elif urgency_count >= 1:
            risk_score += 1
            red_flags.append("Urgency language detected")
        
        # Check for suspicious links
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        for link in links:
            domain = urlparse(link).netloc
            if domain not in PhishingDetector.LEGITIMATE_DOMAINS:
                risk_score += 1
                red_flags.append(f"Suspicious link domain: {domain}")
        
        # Check for requests for personal information
        if re.search(r'\b(password|credit card|social security|account number|pin)\b', body, re.IGNORECASE):
            risk_score += 3
            red_flags.append("Requests for sensitive information")
        
        # Check for misspellings of known companies
        for legit in PhishingDetector.LEGITIMATE_DOMAINS:
            company_name = legit.split('.')[0]
            if company_name in body.lower():
                # Check for common misspellings
                if not re.search(rf'\b{re.escape(company_name)}\b', body.lower()):
                    risk_score += 1
                    red_flags.append(f"Suspicious variation of '{company_name}'")
        
        # Check for suspicious attachments mention
        if re.search(r'\b(download|attachment|open|execute)\b', body, re.IGNORECASE):
            risk_score += 1
            red_flags.append("Suspicious attachment or download request")
        
        # Determine risk level
        risk_level = "Low"
        if risk_score >= 7:
            risk_level = "Critical"
        elif risk_score >= 5:
            risk_level = "High"
        elif risk_score >= 3:
            risk_level = "Medium"
        
        return {
            'sender': sender,
            'risk_score': min(risk_score, 10),  # Cap at 10
            'risk_level': risk_level,
            'red_flags': red_flags,
            'analysis': {
                'sender_analysis': PhishingDetector._analyze_sender(sender),
                'subject_analysis': PhishingDetector._analyze_subject(subject),
                'body_analysis': PhishingDetector._analyze_body(body),
            }
        }
    
    @staticmethod
    def analyze_url(url: str) -> Dict:
        """Analyze URL for phishing indicators."""
        risk_score = 0
        red_flags = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check for suspicious domain characteristics
            if domain.count('.') > 2:  # Subdomains
                risk_score += 1
                red_flags.append("Multiple subdomains (could hide legitimate domain)")
            
            # Check for IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                risk_score += 3
                red_flags.append("Using IP address instead of domain name")
            
            # Check domain for suspicious characters
            if '-' in domain and domain.split('-')[0] in PhishingDetector.LEGITIMATE_DOMAINS:
                risk_score += 2
                red_flags.append("Domain uses legitimate company name with hyphens")
            
            # Check for homograph attacks (0 vs O, l vs 1, etc)
            if re.search(r'[0O]{2,}|[1l]{2,}', domain):
                risk_score += 2
                red_flags.append("Possible homograph attack (similar-looking characters)")
            
            # Check for HTTPS
            if parsed.scheme != 'https':
                risk_score += 1
                red_flags.append("Not using HTTPS (no encryption)")
            
            # Check domain reputation (simplified)
            if domain in PhishingDetector.SUSPICIOUS_DOMAINS:
                risk_score += 3
                red_flags.append("Known suspicious domain")
            
            # Check for embedded credentials in URL
            if '@' in domain:
                risk_score += 2
                red_flags.append("Credentials embedded in URL")
            
        except Exception as e:
            red_flags.append(f"Error parsing URL: {e}")
            risk_score += 2
        
        risk_level = "Low"
        if risk_score >= 7:
            risk_level = "Critical"
        elif risk_score >= 5:
            risk_level = "High"
        elif risk_score >= 3:
            risk_level = "Medium"
        
        return {
            'url': url,
            'risk_score': min(risk_score, 10),
            'risk_level': risk_level,
            'red_flags': red_flags,
        }
    
    @staticmethod
    def _analyze_sender(sender: str) -> Dict:
        """Analyze sender email address."""
        return {
            'address': sender,
            'domain': sender.split('@')[1] if '@' in sender else 'unknown',
            'suspicious': sender.split('@')[1] not in PhishingDetector.LEGITIMATE_DOMAINS if '@' in sender else True,
        }
    
    @staticmethod
    def _analyze_subject(subject: str) -> Dict:
        """Analyze email subject line."""
        urgency_keywords = sum(1 for kw in PhishingDetector.PHISHING_KEYWORDS if kw in subject.lower())
        return {
            'length': len(subject),
            'urgency_keywords': urgency_keywords,
            'all_caps': subject.isupper() and len(subject) > 5,
        }
    
    @staticmethod
    def _analyze_body(body: str) -> Dict:
        """Analyze email body."""
        links = len(re.findall(r'http[s]?://', body))
        return {
            'length': len(body),
            'link_count': links,
            'requests_password': 'password' in body.lower(),
            'requests_credit_card': 'credit card' in body.lower(),
        }


class SecurityAwareness:
    """Security awareness tips and best practices."""
    
    BEST_PRACTICES = [
        "Never click links directly from emails - type the URL in your browser instead",
        "Check for HTTPS and a valid SSL certificate before entering sensitive data",
        "Look for spelling and grammatical errors - legitimate companies proofread their emails",
        "Be suspicious of urgent requests or threats of account closure",
        "Hover over links to see the actual URL destination before clicking",
        "Contact the company directly using contact info from their official website",
        "Never provide passwords or credit card numbers via email",
        "Enable two-factor authentication for important accounts",
        "Keep software and antivirus updated",
        "Report suspicious emails to the company's security team",
    ]
    
    @staticmethod
    def print_tips():
        """Print security awareness tips."""
        print("\n" + "="*60)
        print("SECURITY AWARENESS - PHISHING PREVENTION TIPS")
        print("="*60)
        for i, tip in enumerate(SecurityAwareness.BEST_PRACTICES, 1):
            print(f"{i:2d}. {tip}")
        print("="*60 + "\n")


def main():
    """Interactive demonstration."""
    print("="*60)
    print("Phishing Detector - Social Engineering Awareness Tool")
    print("="*60)
    
    # Email Analysis Example
    print("\n[*] Email Analysis Example:")
    print("-" * 60)
    
    email_sender = "noreply@paypa1.com"
    email_subject = "URGENT: Verify Your Account NOW!"
    email_body = """
Dear User,

Urgent action required! Your PayPal account has unusual activity.
Please click here immediately to verify your credit card and password.

Click: http://verify-paypal-123.com/verify

Do not reply to this email.
Security Team
    """
    
    result = PhishingDetector.analyze_email(email_sender, email_subject, email_body)
    print(f"\nSender: {result['sender']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']}/10)")
    print(f"\nRed Flags:")
    for flag in result['red_flags']:
        print(f"  - {flag}")
    
    # URL Analysis Example
    print("\n\n[*] URL Analysis Example:")
    print("-" * 60)
    
    urls = [
        "https://www.amazon.com/products",
        "http://192.168.1.1/admin",
        "https://amaz0n-security.com/verify",
        "https://paypa1.com:8080/login@realsite.com",
    ]
    
    for url in urls:
        result = PhishingDetector.analyze_url(url)
        print(f"\nURL: {url}")
        print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']}/10)")
        if result['red_flags']:
            print(f"Red Flags:")
            for flag in result['red_flags']:
                print(f"  - {flag}")
    
    # Print security tips
    SecurityAwareness.print_tips()


if __name__ == '__main__':
    main()
