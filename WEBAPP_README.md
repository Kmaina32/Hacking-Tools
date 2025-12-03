# 🌐 Hacking Tools Suite - Web Application

A professional Flask-based web interface for all security tools in the Hacking Tools Suite. Access all tools through a beautiful, responsive dashboard on localhost.

## ✨ Features

✅ **Modern Web Interface**
- Responsive design that works on desktop, tablet, and mobile
- Dark theme optimized for security work
- Real-time results and live feedback

✅ **All 9 Tools Available**
- Port Scanner
- Network Mapper (coming soon in web)
- Caesar Cipher
- Vigenère Cipher
- Base64 Encoder/Decoder
- Hash Generator (MD5, SHA1, SHA256, SHA512)
- SQL Injection Tester
- XSS Vulnerability Tester
- Password Strength Analyzer
- Phishing Detector (Email & URL)

✅ **Easy to Use**
- Intuitive tool sidebar
- Category-based filtering
- Quick access to common payloads
- Real-time validation

✅ **RESTful API**
- JSON-based API endpoints
- Can be used by other applications
- Extensible architecture

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

This installs Flask and all required packages.

### 2. Start the Web Server

**Windows:**
```bash
run_webapp.bat
```

Or manually:
```bash
python app.py
```

**Linux/macOS:**
```bash
bash run_webapp.sh
```

Or manually:
```bash
python3 app.py
```

### 3. Access the Application

Open your browser and go to:
```
http://localhost:5000
```

You should see the Hacking Tools Suite dashboard.

---

## 📖 Usage Guide

### Tool Categories

**Network Tools** 🌐
- Port Scanner - Scan for open ports on target hosts
- Network Mapper - Discover active hosts on networks

**Cryptography** 🔐
- Caesar Cipher - Simple shift cipher encryption/decryption
- Vigenère Cipher - Polyalphabetic substitution
- Base64 Encoder - Base64 encoding/decoding
- Hash Generator - Generate hashes (MD5, SHA1, SHA256, SHA512)

**Web Security** 🎯
- SQL Injection Tester - Test for SQL injection vulnerabilities
- XSS Tester - Detect cross-site scripting vectors

**Password** 🔑
- Password Strength Analyzer - Analyze password strength and entropy

**Social Engineering** ⚠️
- Phishing Detector - Analyze emails and URLs for phishing threats

### Common Tasks

#### Port Scanning
1. Click "Port Scanner" from the sidebar
2. Enter target (localhost, 192.168.1.1, example.com)
3. Enter port range (1-1000, 80,443,8080, etc.)
4. Click "Scan Ports"

#### Encrypting with Caesar Cipher
1. Click "Caesar Cipher" from the sidebar
2. Enter text to encrypt
3. Set shift value (1-25)
4. Select mode (Encrypt, Decrypt, or Brute Force)
5. Click "Process"

#### Testing for SQL Injection
1. Click "SQL Injection Tester"
2. Enter user input to test
3. Click "Test for SQL Injection"
4. Review vulnerability report

#### Analyzing Password Strength
1. Click "Password Strength Analyzer"
2. Enter a password
3. Click "Analyze Password"
4. View strength score, entropy, and feedback

#### Detecting Phishing
1. Click "Phishing Detector"
2. Choose Email Analysis or URL Analysis
3. Fill in the required fields
4. Click the analyze button
5. Review risk level and red flags

---

## 🔌 API Documentation

The web application exposes a RESTful API that can be used by other applications or scripts.

### Base URL
```
http://localhost:5000
```

### Endpoints

#### Get Available Tools
```
GET /api/tools
```

#### Port Scanner
```
POST /api/scan/port
Content-Type: application/json

{
  "target": "localhost",
  "ports": "1-1000",
  "timeout": 1,
  "threads": 50
}
```

#### Caesar Cipher
```
POST /api/crypto/caesar
Content-Type: application/json

{
  "text": "HELLO WORLD",
  "shift": 3,
  "mode": "encrypt"  // encrypt, decrypt, brute_force
}
```

#### Vigenère Cipher
```
POST /api/crypto/vigenere
Content-Type: application/json

{
  "text": "HELLO WORLD",
  "key": "SECRET",
  "mode": "encrypt"  // encrypt, decrypt
}
```

#### Base64 Encoding
```
POST /api/crypto/base64
Content-Type: application/json

{
  "text": "HELLO WORLD",
  "mode": "encode"  // encode, decode
}
```

#### Hash Generation
```
POST /api/crypto/hash
Content-Type: application/json

{
  "text": "password123",
  "algorithm": "sha256"  // md5, sha1, sha256, sha512
}
```

#### SQL Injection Testing
```
POST /api/security/sql-injection
Content-Type: application/json

{
  "input": "' OR '1'='1"
}
```

#### XSS Testing
```
POST /api/security/xss
Content-Type: application/json

{
  "input": "<script>alert('XSS')</script>"
}
```

#### Password Strength Analysis
```
POST /api/password/strength
Content-Type: application/json

{
  "password": "MyP@ssw0rd!"
}
```

#### Phishing Email Analysis
```
POST /api/phishing/analyze-email
Content-Type: application/json

{
  "sender": "sender@example.com",
  "subject": "Email subject",
  "body": "Email body content"
}
```

#### Phishing URL Analysis
```
POST /api/phishing/analyze-url
Content-Type: application/json

{
  "url": "https://example.com"
}
```

#### Security Tips
```
GET /api/security/tips
```

---

## 🛠️ Configuration

### Change Port
To run on a different port, edit `app.py`:

```python
if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=8080)  # Change 5000 to your port
```

### Enable Remote Access
To allow connections from other machines:

```python
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # 0.0.0.0 allows all IPs
```

### Disable Debug Mode
For production (not recommended without proper security):

```python
if __name__ == '__main__':
    app.run(debug=False, host='localhost', port=5000)
```

---

## 🐛 Troubleshooting

### "Flask not found" Error
```bash
pip install flask flask-cors
```

### Port 5000 Already in Use
Change the port in `app.py` or find what's using it:

**Windows:**
```bash
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

**Linux/macOS:**
```bash
lsof -i :5000
kill -9 <PID>
```

### Can't Connect to localhost:5000
- Make sure the Flask server is running
- Check that no firewall is blocking port 5000
- Try `http://127.0.0.1:5000` instead

### Tools Not Loading
1. Verify all dependencies are installed: `pip install -r requirements.txt`
2. Check Python version (3.7+ required)
3. Check Flask application logs for errors

### API Errors
- Check request format (must be valid JSON)
- Verify Content-Type is `application/json`
- Check required parameters are provided

---

## 📁 File Structure

```
hacking_tools/
├── app.py                      Main Flask application
├── run_webapp.bat              Windows launcher
├── run_webapp.sh               Linux/macOS launcher
├── templates/
│   └── index.html             Main web interface
├── static/
│   ├── css/
│   │   └── style.css          Styling
│   └── js/
│       └── main.js            Frontend logic
└── hacking_tools/             (Tool modules)
    ├── network_tools/
    ├── cryptography_tools/
    ├── web_security/
    ├── password_tools/
    └── social_engineering/
```

---

## 🔐 Security Considerations

### ⚠️ Important
1. **This is a local development tool** - Not designed for production
2. **Never expose to the internet** without proper authentication
3. **Local use only** - Use on localhost or trusted networks only
4. **Debug mode is enabled** - Disable in production environments
5. **No authentication** - Anyone with access to port 5000 can use the tools

### Best Practices
- Use only on localhost (127.0.0.1)
- Disable debug mode for production use
- Implement authentication if exposing to network
- Use HTTPS if accessing remotely
- Monitor logs for suspicious activity

---

## 🚀 Advanced Usage

### Using the API with cURL

**Port Scan:**
```bash
curl -X POST http://localhost:5000/api/scan/port \
  -H "Content-Type: application/json" \
  -d '{"target":"localhost","ports":"1-1000"}'
```

**Hash Generation:**
```bash
curl -X POST http://localhost:5000/api/crypto/hash \
  -H "Content-Type: application/json" \
  -d '{"text":"password123","algorithm":"sha256"}'
```

**SQL Injection Test:**
```bash
curl -X POST http://localhost:5000/api/security/sql-injection \
  -H "Content-Type: application/json" \
  -d '{"input":"'"'"' OR '"'"'1'"'"'='"'"'1"}'
```

### Using the API with Python

```python
import requests
import json

# API base URL
api_url = "http://localhost:5000"

# Test SQL Injection
response = requests.post(
    f"{api_url}/api/security/sql-injection",
    json={"input": "' OR '1'='1"}
)
print(response.json())

# Generate Hash
response = requests.post(
    f"{api_url}/api/crypto/hash",
    json={"text": "password", "algorithm": "sha256"}
)
print(response.json())

# Analyze Password
response = requests.post(
    f"{api_url}/api/password/strength",
    json={"password": "MyP@ssw0rd!"}
)
print(response.json())
```

---

## 📝 Logging

Flask logs all requests to the console. You can redirect to a file:

**Windows:**
```bash
python app.py > webapp.log 2>&1
```

**Linux/macOS:**
```bash
python3 app.py | tee webapp.log
```

---

## 🔄 Extending the Application

### Adding a New Tool

1. Create API endpoint in `app.py`:
```python
@app.route('/api/my-tool', methods=['POST'])
def my_tool():
    data = request.get_json()
    # Process data
    return jsonify({'result': 'output'})
```

2. Add tool to frontend in `static/js/main.js`:
```javascript
async function myToolFunction() {
    const response = await fetch('/api/my-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ /* data */ })
    });
    const data = await response.json();
    // Handle response
}
```

3. Update tools list in `get_tools()` function

---

## 📞 Support

For issues with:
- **Web interface**: Check browser console (F12)
- **API**: Check Flask server logs
- **Tools**: Refer to individual tool documentation in main README.md
- **Installation**: See troubleshooting section above

---

## ⚖️ Legal Notice

> This web application is for **EDUCATIONAL PURPOSES ONLY**
>
> Unauthorized access to computer systems is **ILLEGAL**
> 
> Only use on systems you own or have explicit permission to test

---

## 🎓 Learning Resources

- Flask Documentation: https://flask.palletsprojects.com/
- REST API Design: https://restfulapi.net/
- Web Security: https://owasp.org/

---

**Happy learning! 🚀**
