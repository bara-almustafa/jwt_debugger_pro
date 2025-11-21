# JWT Debugger Pro

Advanced, client-side JSON Web Token debugger and security analyzer for decoding, verifying, building, and stress-testing JWTs directly in the browser.

## 🚀 Live Demo

**[Launch JWT Debugger Pro](https://bara-almustafa.github.io/jwt_debugger_pro/)**

---

## ✨ Key Features

### 🔍 **Decode & Verify**
- **Real-time Decoding**: Instantly parse headers, payloads, and signatures.
- **Visual Validation**: Color-coded status for valid/invalid tokens.
- **Time-Travel Debugging**: Human-readable timestamps for `exp`, `iat`, and `nbf` with visual "Active/Expired" status indicators.
- **Signature Verification**: Supports HMAC (HS256/384/512) and RSA/ECDSA verification.

### 🛠️ **Encode & Sign**
- **Interactive Builder**: Craft custom tokens using a clean JSON editor.
- **Quick Actions**: One-click buttons to add standard claims (e.g., "Add Expiration").
- **Key Management**: Input custom secrets or private keys to sign your own tokens.

### 🛡️ **Security Analyzer**
A built-in vulnerability scanner that checks for:
- ❌ **"None" Algorithm**: Detects unsecured tokens.
- 🔓 **Weak Secrets**: Identifies short or dictionary-based secrets.
- ⚠️ **Algorithm Confusion**: Warns about potential key mismanagement risks.
- 🕷️ **Header Injection**: Checks for dangerous `jku`/`jwk` parameters.

### 🔨 **Brute Force Tool** (Educational)
- **Dictionary Attack Simulator**: Test token strength against a list of common weak secrets.
- **Performance Metrics**: View attempts per second to understand cryptographic strength.
- **Disclaimer**: STRICTLY for educational use on tokens you own.

---

## 🔒 Privacy First
**100% Client-Side Execution**: 
- This application runs entirely in your browser.
- No backend server is involved.
- Your tokens, keys, and secrets **never** leave your device.
- You can verify this by inspecting the source code or running offline.

---

## 💻 Tech Stack
- **Core**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Crypto**: Native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (SubtleCrypto)
- **Styling**: CSS Grid & Flexbox (No external UI frameworks)
- **Deployment**: GitHub Pages

---

## 🏃‍♂️ How to Run Locally

If you want to run this tool on your own machine:

1. **Clone the repository**
git clone https://github.com/bara-almustafa/jwt_debugger_pro.git
2. **Navigate to the folder**
cd jwt_debugger_pro

text

3. **Launch**
Simply open `index.html` in your web browser.

*Note: For the best experience with Web Crypto APIs, it is recommended to use a simple local server:*
Python 3
python -m http.server 8000

Node.js
npx http-server

text
Then visit `http://localhost:8000`.

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new security checks or UI improvements:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is provided for **educational and testing purposes only**. The author allows the use of this software only on systems where you have explicit permission to test. Misuse of this software for malicious activities is strictly prohibited.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

*Built with ❤️ for the security community.*
