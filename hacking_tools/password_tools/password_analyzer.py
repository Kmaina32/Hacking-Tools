"""
Password Analysis Tools
=======================
Educational tools for understanding password security concepts.
Includes password strength checking and hash cracking utilities.
"""

import hashlib
import re
from typing import Dict, List, Tuple
import time


class PasswordStrengthAnalyzer:
    """Analyze password strength."""
    
    @staticmethod
    def analyze(password: str) -> Dict:
        """Analyze password strength and return metrics."""
        score = 0
        feedback = []
        
        # Length checks
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password is too short (minimum 8 characters)")
        
        if len(password) >= 12:
            score += 1
        
        if len(password) >= 16:
            score += 1
        
        # Character type checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        # Common patterns check
        common_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if any(pattern in password.lower() for pattern in common_patterns):
            score = max(0, score - 2)
            feedback.append("Contains common password patterns")
        
        # Determine strength level
        strength_levels = {
            0: "Very Weak",
            1: "Weak",
            2: "Fair",
            3: "Good",
            4: "Strong",
            5: "Very Strong",
            6: "Excellent",
            7: "Excellent",
        }
        
        return {
            'password': len(password) * '*',  # Don't expose actual password
            'length': len(password),
            'score': score,
            'strength': strength_levels.get(score, "Excellent"),
            'feedback': feedback,
            'entropy': PasswordStrengthAnalyzer.calculate_entropy(password),
        }
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy in bits."""
        import math
        
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^\w\s]', password):
            charset_size += 32  # Special characters
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)


class HashCracker:
    """Educational hash cracking tool using dictionary attacks."""
    
    # Common passwords for dictionary attack
    COMMON_PASSWORDS = [
        'password', 'password123', '123456', '12345678', 'qwerty',
        'abc123', 'monkey', '1234567', 'letmein', 'trustno1',
        'dragon', 'baseball', '111111', 'iloveyou', 'master',
        'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
    ]
    
    @staticmethod
    def generate_wordlist(base_words: List[str], max_variations: int = 3) -> List[str]:
        """Generate wordlist with common variations."""
        wordlist = set()
        
        for word in base_words:
            wordlist.add(word)
            wordlist.add(word.upper())
            wordlist.add(word.capitalize())
            
            # Add common suffixes
            for suffix in ['', '1', '2', '3', '!', '@', '#', '123', '2023', '2024']:
                wordlist.add(word + suffix)
        
        return list(wordlist)
    
    @staticmethod
    def crack_md5(target_hash: str, wordlist: List[str] = None) -> Tuple[bool, str]:
        """Attempt to crack MD5 hash."""
        if wordlist is None:
            wordlist = HashCracker.generate_wordlist(HashCracker.COMMON_PASSWORDS)
        
        print(f"[*] Attempting to crack MD5 hash: {target_hash}")
        print(f"[*] Wordlist size: {len(wordlist)}")
        
        for i, word in enumerate(wordlist):
            hash_value = hashlib.md5(word.encode()).hexdigest()
            
            if i % 100 == 0:
                print(f"[*] Progress: {i}/{len(wordlist)} attempts")
            
            if hash_value == target_hash:
                print(f"[+] FOUND! Password is: {word}")
                return True, word
        
        print("[!] Password not found in wordlist")
        return False, None
    
    @staticmethod
    def crack_sha256(target_hash: str, wordlist: List[str] = None) -> Tuple[bool, str]:
        """Attempt to crack SHA256 hash."""
        if wordlist is None:
            wordlist = HashCracker.generate_wordlist(HashCracker.COMMON_PASSWORDS)
        
        print(f"[*] Attempting to crack SHA256 hash: {target_hash}")
        print(f"[*] Wordlist size: {len(wordlist)}")
        
        for i, word in enumerate(wordlist):
            hash_value = hashlib.sha256(word.encode()).hexdigest()
            
            if i % 100 == 0:
                print(f"[*] Progress: {i}/{len(wordlist)} attempts")
            
            if hash_value == target_hash:
                print(f"[+] FOUND! Password is: {word}")
                return True, word
        
        print("[!] Password not found in wordlist")
        return False, None


def main():
    """Interactive demonstration."""
    print("="*60)
    print("Password Analysis Tools - Educational Tool")
    print("="*60)
    
    # Password Strength Analysis
    print("\n[*] Password Strength Analysis:")
    print("-" * 60)
    
    test_passwords = [
        'password',
        'Pass123',
        'MyP@ssw0rd!',
        '2024SecureP@ss',
    ]
    
    for pwd in test_passwords:
        analysis = PasswordStrengthAnalyzer.analyze(pwd)
        print(f"\n  Password Length: {analysis['length']}")
        print(f"  Strength: {analysis['strength']} (Score: {analysis['score']}/7)")
        print(f"  Entropy: {analysis['entropy']} bits")
        if analysis['feedback']:
            print(f"  Feedback:")
            for tip in analysis['feedback']:
                print(f"    - {tip}")
    
    # Hash Cracking Demo
    print("\n\n[*] Hash Cracking Demo:")
    print("-" * 60)
    
    # Create test hash
    test_password = "dragon"
    test_hash_md5 = hashlib.md5(test_password.encode()).hexdigest()
    test_hash_sha256 = hashlib.sha256(test_password.encode()).hexdigest()
    
    print(f"\n  Test Password: {test_password}")
    print(f"  MD5 Hash: {test_hash_md5}")
    print(f"  SHA256 Hash: {test_hash_sha256}")
    
    print(f"\n  Attempting to crack MD5...")
    found, result = HashCracker.crack_md5(test_hash_md5)
    
    print(f"\n  Attempting to crack SHA256...")
    found, result = HashCracker.crack_sha256(test_hash_sha256)


if __name__ == '__main__':
    main()
