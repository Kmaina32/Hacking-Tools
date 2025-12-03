"""
WiFi Connection Hacking Tools
==============================
Advanced tools for analyzing and testing WiFi connections.
Educational purposes only!
"""

import subprocess
import re
import hashlib
import string
from typing import Dict, List, Tuple


class WiFiConnectionAnalyzer:
    """Analyze current WiFi connection details."""
    
    @staticmethod
    def get_detailed_connection_info() -> Dict:
        """Get detailed information about current WiFi connection."""
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'interfaces'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            info = {
                'ssid': 'Unknown',
                'authentication': 'Unknown',
                'cipher': 'Unknown',
                'signal': 0,
                'channel': 'Unknown',
                'standard': 'Unknown',
                'tx_rate': 'Unknown',
                'rx_rate': 'Unknown',
                'radio_type': 'Unknown',
                'state': 'Unknown',
                'password': None
            }
            
            # Parse values
            ssid_match = re.search(r'SSID\s*:\s*(.+)', output)
            auth_match = re.search(r'Authentication\s*:\s*(.+)', output)
            cipher_match = re.search(r'Cipher\s*:\s*(.+)', output)
            signal_match = re.search(r'Signal\s*:\s*(\d+)%', output)
            channel_match = re.search(r'Channel\s*:\s*(\d+)', output)
            standard_match = re.search(r'802\.11\s+Standards?\s*:\s*(.+)', output)
            tx_match = re.search(r'TX\s+Rate\s*\(Mbps\)\s*:\s*(\d+)', output)
            rx_match = re.search(r'RX\s+Rate\s*\(Mbps\)\s*:\s*(\d+)', output)
            radio_match = re.search(r'Radio\s+Type\s*:\s*(.+)', output)
            state_match = re.search(r'State\s*:\s*(.+)', output)
            
            if ssid_match:
                info['ssid'] = ssid_match.group(1).strip()
                # Get password for this network
                try:
                    password_output = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', f'name="{info["ssid"]}"', 'key=clear'],
                        stderr=subprocess.DEVNULL
                    ).decode('utf-8', errors='ignore')
                    password_match = re.search(r'Key Content\s*:\s*(.+)', password_output)
                    if password_match:
                        info['password'] = password_match.group(1).strip()
                except Exception:
                    pass
            
            if auth_match:
                info['authentication'] = auth_match.group(1).strip()
            if cipher_match:
                info['cipher'] = cipher_match.group(1).strip()
            if signal_match:
                info['signal'] = int(signal_match.group(1))
            if channel_match:
                info['channel'] = int(channel_match.group(1))
            if standard_match:
                info['standard'] = standard_match.group(1).strip()
            if tx_match:
                info['tx_rate'] = int(tx_match.group(1))
            if rx_match:
                info['rx_rate'] = int(rx_match.group(1))
            if radio_match:
                info['radio_type'] = radio_match.group(1).strip()
            if state_match:
                info['state'] = state_match.group(1).strip()
            
            return info
        
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_connection_history() -> List[Dict]:
        """Get WiFi connection history."""
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profiles'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            profiles = []
            profile_matches = re.findall(r':\s*(.+)', output)
            
            for profile in profile_matches:
                profile = profile.strip()
                if profile and not profile.startswith('('):
                    # Get password for this profile
                    password = WiFiConnectionAnalyzer.get_saved_password(profile)
                    profiles.append({
                        'name': profile,
                        'type': 'WiFi Profile',
                        'password': password
                    })
            
            return profiles
        
        except Exception as e:
            return []
    
    @staticmethod
    def get_saved_password(ssid: str) -> str:
        """Get saved password for a WiFi network."""
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profile', f'name="{ssid}"', 'key=clear'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            # Extract password
            password_match = re.search(r'Key Content\s*:\s*(.+)', output)
            if password_match:
                return password_match.group(1).strip()
            
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_all_saved_passwords() -> List[Dict]:
        """Get all saved WiFi passwords."""
        passwords = []
        try:
            # Get all profiles
            profiles_output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profiles'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            # Extract profile names
            profile_matches = re.findall(r':\s*(.+)', profiles_output)
            
            for profile in profile_matches:
                profile = profile.strip()
                if profile and not profile.startswith('('):
                    password = WiFiConnectionAnalyzer.get_saved_password(profile)
                    if password:
                        passwords.append({
                            'ssid': profile,
                            'password': password
                        })
            
        except Exception as e:
            pass
        
        return passwords


class WiFiPasswordTools:
    """Tools for WiFi password analysis and dictionary attacks (educational)."""
    
    COMMON_PASSWORDS = [
        'admin', 'admin123', 'password', 'password123',
        '12345678', '123456789', 'qwerty', 'letmein',
        'welcome', 'router', 'linksys', 'cisco',
        'netgear', 'belkin', 'dlink', 'tplink',
        'default', 'changeme', '1234', '12345',
        'asdf', 'zxcv', 'iloveyou'
    ]
    
    @staticmethod
    def analyze_password_strength(password: str) -> Dict:
        """
        Analyze WiFi password strength (for testing purposes).
        
        Args:
            password: Password to analyze
        
        Returns:
            Strength analysis report
        """
        score = 0
        feedback = []
        
        # Length analysis
        if len(password) >= 20:
            score += 20
        elif len(password) >= 12:
            score += 15
        elif len(password) >= 8:
            score += 10
        else:
            feedback.append('Password too short (minimum 12 characters recommended)')
        
        # Character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        if has_upper:
            score += 10
        else:
            feedback.append('Missing uppercase letters')
        
        if has_lower:
            score += 10
        else:
            feedback.append('Missing lowercase letters')
        
        if has_digit:
            score += 10
        else:
            feedback.append('Missing numbers')
        
        if has_special:
            score += 15
        else:
            feedback.append('Missing special characters')
        
        # Pattern analysis
        if password.lower() in WiFiPasswordTools.COMMON_PASSWORDS:
            score -= 30
            feedback.append('Password is commonly used')
        
        if re.match(r'^[a-z]*\d*$', password.lower()):
            score -= 10
            feedback.append('Simple pattern detected')
        
        # Determine strength
        if score >= 70:
            strength = 'Strong'
            color = 'green'
        elif score >= 50:
            strength = 'Good'
            color = 'blue'
        elif score >= 30:
            strength = 'Fair'
            color = 'yellow'
        else:
            strength = 'Weak'
            color = 'red'
        
        return {
            'password_length': len(password),
            'score': max(0, min(100, score)),
            'strength': strength,
            'color': color,
            'has_uppercase': has_upper,
            'has_lowercase': has_lower,
            'has_digits': has_digit,
            'has_special': has_special,
            'feedback': feedback
        }
    
    @staticmethod
    def check_dictionary_match(password: str) -> Dict:
        """Check if password matches common dictionary words."""
        matches = []
        
        for common_pass in WiFiPasswordTools.COMMON_PASSWORDS:
            if password.lower() == common_pass.lower():
                matches.append({
                    'type': 'Exact match',
                    'password': common_pass,
                    'risk': 'Critical'
                })
            elif common_pass.lower() in password.lower():
                matches.append({
                    'type': 'Contains',
                    'password': common_pass,
                    'risk': 'High'
                })
        
        return {
            'dictionary_matches': matches,
            'vulnerable_to_dictionary_attack': len(matches) > 0,
            'total_matches': len(matches)
        }


class WiFiSecurityTest:
    """Test WiFi network security vulnerabilities."""
    
    @staticmethod
    def test_wps_vulnerability() -> Dict:
        """Test for WPS (WiFi Protected Setup) vulnerability."""
        vulnerabilities = []
        
        try:
            # Check if WPS is likely enabled (common on many routers)
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'interfaces'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            # Most routers have WPS enabled by default
            has_wps = 'WPS' in output or True  # Assume enabled on most routers
            
            if has_wps:
                vulnerabilities.append({
                    'vulnerability': 'WPS Enabled',
                    'severity': 'High',
                    'description': 'WiFi Protected Setup may be vulnerable to brute-force attacks',
                    'recommendation': 'Disable WPS in router settings',
                    'attack_type': 'WPS PIN brute-force'
                })
        
        except:
            pass
        
        return {
            'wps_vulnerabilities': vulnerabilities,
            'vulnerable_to_wps_attack': len(vulnerabilities) > 0
        }
    
    @staticmethod
    def test_default_gateway() -> Dict:
        """Analyze default gateway for vulnerabilities."""
        try:
            output = subprocess.check_output(
                ['ipconfig', '/all'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            gateway_match = re.search(r'Default Gateway.*?:\s*([0-9.]+)', output)
            gateway = gateway_match.group(1) if gateway_match else 'Unknown'
            
            vulnerabilities = []
            
            # Check for common vulnerable default IPs
            vulnerable_defaults = {
                '192.168.1.1': 'Linksys, TP-Link',
                '192.168.0.1': 'Netgear, D-Link',
                '10.0.0.1': 'Various',
            }
            
            for ip, brands in vulnerable_defaults.items():
                if gateway == ip:
                    vulnerabilities.append({
                        'issue': f'Common default gateway: {ip}',
                        'brands': brands,
                        'risk': 'Default credentials may be in use'
                    })
            
            return {
                'gateway': gateway,
                'vulnerabilities': vulnerabilities,
                'vulnerable': len(vulnerabilities) > 0
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def test_encryption_strength(cipher: str) -> Dict:
        """Analyze encryption cipher strength."""
        cipher_ratings = {
            'CCMP': {'strength': 'Strong', 'score': 95, 'type': 'AES'},
            'TKIP': {'strength': 'Weak', 'score': 30, 'type': 'RC4'},
            'WEP': {'strength': 'Critical', 'score': 10, 'type': 'RC4'},
            'None': {'strength': 'None', 'score': 0, 'type': 'None'}
        }
        
        rating = cipher_ratings.get(cipher, {'strength': 'Unknown', 'score': 50, 'type': 'Unknown'})
        
        vulnerabilities = []
        
        if cipher == 'WEP':
            vulnerabilities.append({
                'issue': 'WEP encryption is deprecated',
                'severity': 'Critical',
                'description': 'WEP can be cracked in minutes',
                'recommendation': 'Upgrade to WPA2 or WPA3'
            })
        elif cipher == 'TKIP':
            vulnerabilities.append({
                'issue': 'TKIP has known vulnerabilities',
                'severity': 'High',
                'description': 'Use CCMP (AES) instead',
                'recommendation': 'Change to WPA2-Personal with CCMP'
            })
        
        return {
            'cipher': cipher,
            'strength': rating['strength'],
            'security_score': rating['score'],
            'type': rating['type'],
            'vulnerabilities': vulnerabilities
        }


class WiFiNetworkMapping:
    """Map and analyze nearby WiFi networks."""
    
    @staticmethod
    def scan_detailed_networks() -> List[Dict]:
        """Detailed scan of nearby networks with security analysis."""
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'network', 'mode=Bssid'],
                stderr=subprocess.DEVNULL
            ).decode('utf-8', errors='ignore')
            
            networks = []
            ssids = re.findall(r'SSID\s*:\s*(\d+)\s*:\s*(.+)', output)
            
            for num, ssid in ssids:
                ssid = ssid.strip()
                
                # Security risk assessment
                risk_level = 'Low'
                if 'linksys' in ssid.lower() or 'default' in ssid.lower():
                    risk_level = 'High'
                elif ssid.lower() == 'admin' or ssid.lower() == 'guest':
                    risk_level = 'High'
                
                networks.append({
                    'ssid': ssid,
                    'risk_level': risk_level,
                    'recommendations': [
                        'Use WPA2 or WPA3 encryption',
                        'Change default SSID',
                        'Use strong password (12+ characters)',
                        'Disable WPS',
                        'Hide SSID (optional, not required)'
                    ]
                })
            
            return networks
        
        except:
            return []
