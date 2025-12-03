"""
Cipher Tools - Encryption & Decryption Utilities
================================================
Educational tools for understanding various cipher techniques.
Includes Caesar, ROT13, Vigenère, and Base64 ciphers.
"""

import base64
import hashlib
from typing import Union


class CaesarCipher:
    """Caesar cipher implementation."""
    
    @staticmethod
    def encrypt(plaintext: str, shift: int = 3) -> str:
        """Encrypt text using Caesar cipher."""
        result = []
        shift = shift % 26
        
        for char in plaintext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(ciphertext: str, shift: int = 3) -> str:
        """Decrypt text using Caesar cipher."""
        return CaesarCipher.encrypt(ciphertext, -shift)
    
    @staticmethod
    def brute_force(ciphertext: str) -> dict:
        """Brute force Caesar cipher (try all 26 shifts)."""
        results = {}
        for shift in range(26):
            results[shift] = CaesarCipher.decrypt(ciphertext, shift)
        return results


class VigenereCipher:
    """Vigenère cipher implementation."""
    
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """Encrypt text using Vigenère cipher."""
        if not key:
            raise ValueError("Key cannot be empty")
        
        key = key.upper()
        result = []
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = ord(key[key_index % len(key)]) - ord('A')
                encrypted = (ord(char) - base + shift) % 26
                result.append(chr(base + encrypted))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        """Decrypt text using Vigenère cipher."""
        if not key:
            raise ValueError("Key cannot be empty")
        
        key = key.upper()
        result = []
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = ord(key[key_index % len(key)]) - ord('A')
                decrypted = (ord(char) - base - shift) % 26
                result.append(chr(base + decrypted))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)


class Base64Cipher:
    """Base64 encoding/decoding."""
    
    @staticmethod
    def encode(text: str) -> str:
        """Encode text to Base64."""
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def decode(encoded: str) -> str:
        """Decode Base64 text."""
        try:
            return base64.b64decode(encoded).decode()
        except Exception as e:
            raise ValueError(f"Invalid Base64 string: {e}")


class HashTools:
    """Hashing utilities for cryptographic hash functions."""
    
    @staticmethod
    def md5(text: str) -> str:
        """Generate MD5 hash."""
        return hashlib.md5(text.encode()).hexdigest()
    
    @staticmethod
    def sha1(text: str) -> str:
        """Generate SHA1 hash."""
        return hashlib.sha1(text.encode()).hexdigest()
    
    @staticmethod
    def sha256(text: str) -> str:
        """Generate SHA256 hash."""
        return hashlib.sha256(text.encode()).hexdigest()
    
    @staticmethod
    def sha512(text: str) -> str:
        """Generate SHA512 hash."""
        return hashlib.sha512(text.encode()).hexdigest()


def main():
    """Interactive demonstration."""
    print("="*50)
    print("Cipher Tools - Educational Demonstration")
    print("="*50)
    
    # Caesar Cipher Example
    print("\n[*] Caesar Cipher:")
    text = "HELLO WORLD"
    encrypted = CaesarCipher.encrypt(text, 3)
    print(f"    Original: {text}")
    print(f"    Encrypted (shift=3): {encrypted}")
    print(f"    Decrypted: {CaesarCipher.decrypt(encrypted, 3)}")
    
    # Vigenère Cipher Example
    print("\n[*] Vigenère Cipher:")
    text = "HELLO WORLD"
    key = "SECRET"
    encrypted = VigenereCipher.encrypt(text, key)
    print(f"    Original: {text}")
    print(f"    Key: {key}")
    print(f"    Encrypted: {encrypted}")
    print(f"    Decrypted: {VigenereCipher.decrypt(encrypted, key)}")
    
    # Base64 Example
    print("\n[*] Base64 Encoding:")
    text = "HELLO WORLD"
    encoded = Base64Cipher.encode(text)
    print(f"    Original: {text}")
    print(f"    Encoded: {encoded}")
    print(f"    Decoded: {Base64Cipher.decode(encoded)}")
    
    # Hash Examples
    print("\n[*] Hashing:")
    text = "password123"
    print(f"    Text: {text}")
    print(f"    MD5: {HashTools.md5(text)}")
    print(f"    SHA256: {HashTools.sha256(text)}")
    
    # Caesar Brute Force
    print("\n[*] Caesar Cipher Brute Force Attack:")
    ciphertext = "KHOOR ZRUOG"
    print(f"    Ciphertext: {ciphertext}")
    print("    Trying all shifts (1-5):")
    results = CaesarCipher.brute_force(ciphertext)
    for shift in range(1, 6):
        print(f"      Shift {shift}: {results[shift]}")


if __name__ == '__main__':
    main()
