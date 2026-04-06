# PQC File Encryptor

A browser-based file encryption system with dual-mode support: post-quantum keypair encryption (ML-KEM-768) and password-based encryption (PBKDF2-SHA256). Secure your sensitive files with zero server involvement.

## Features

- **Two Encryption Modes**:
  - 🔑 **Keypair Mode** — Post-quantum security with ML-KEM-768 (NIST FIPS 203)
  - 🔒 **Password Mode** — Quick sharing with a generated strong password
- **Built-in Password Generator** — 24-character cryptographically random passwords (~158 bits entropy)
- **Password Strength Meter** — Real-time entropy estimation for user-typed passwords
- **Client-Side Only** — All encryption/decryption happens in your browser. No data is ever transmitted.
- **AES-256-GCM** — Authenticated encryption for file content
- **Dark Mode** — Built-in theme toggle
- **Docker Support** — Self-contained deployment, entire image under 100MB

## Quick Start

### Option 1: Local Server

```bash
# Python 3
python -m http.server 8080

# Node.js
npx serve .
```

Open http://localhost:8080 in your browser.

### Option 2: Docker

```bash
docker-compose up --build
```

Open http://localhost:8080 in your browser.

## Usage

### Keypair Mode (Post-Quantum)

Best for long-term secure communication with known recipients.

1. **Generate Keypair** — Click **"Generate Keypair"** then download both:
   - Public Key (safe to share)
   - Private Key (keep secret!)
2. **Encrypt** — Import recipient's **Public Key**, select a file, click **"Encrypt File"**
3. **Decrypt** — Import your **Private Key**, select the `.pqenc.json`, click **"Decrypt File"**

### Password Mode (Quick Share)

Best for one-off file sharing with anyone — no key setup required.

1. **Encrypt** — Switch to **🔒 Password** mode, click **🎲 Generate** for a strong password, select a file, click **"Encrypt File"**
2. **Share** — Send the encrypted file via any channel. Share the password via a separate channel (Signal, verbal, etc.)
3. **Decrypt** — Recipient opens the same tool, switches to **🔒 Password** mode, selects the encrypted file, enters the password, clicks **"Decrypt File"**

## Security

### Keypair Mode
- **Key Encapsulation**: ML-KEM-768 (post-quantum)
- **Key Derivation**: HKDF-SHA-256
- **Key Wrapping**: AES-256-KW
- **Encryption**: AES-256-GCM with authenticated encryption

### Password Mode
- **Key Derivation**: PBKDF2-SHA256 with 600,000 iterations (OWASP 2026 minimum)
- **Salt**: 16-byte random per envelope (prevents rainbow table attacks)
- **Key Wrapping**: AES-256-KW
- **Encryption**: AES-256-GCM with authenticated encryption

See [docs/SECURITY.md](docs/SECURITY.md) for details.

## Choosing a Mode

| Scenario | Recommended Mode |
|---|---|
| Sharing with a new freelancer/contractor | 🔒 Password |
| Long-term team communication | 🔑 Keypair |
| Backing up config files to cloud storage | 🔒 Password |
| Highly sensitive data (production secrets) | 🔑 Keypair |
| Quick file exchange in a meeting | 🔒 Password |
| Multiple recipients | 🔑 Keypair |

## File Support

| Type | Extension | Max Size |
|------|-----------|----------|
| Plain text | `.txt` | 10MB |
| Environment | `.env` | 10MB |
| Encrypted | `.pqenc.json` | 10MB |

## Technology Stack

- **Cryptography**: @noble/post-quantum (ML-KEM-768), WebCrypto API (PBKDF2, AES-GCM, AES-KW, HKDF)
- **Web Crypto**: Native browser APIs
- **Runtime**: Pure JavaScript (no server required)

## Browser Support

- Chrome/Edge 90+
- Firefox 90+
- Safari 15+

Requires WebCrypto API and ES Modules.

## Project Structure

```
files_Encryption/
├── index.html          # Main UI
├── styles.css          # Styles + dark mode
├── app.js              # Application logic
├── lib/
│   ├── utils.js        # File I/O, encoding, password utilities
│   ├── crypto.js       # ML-KEM-768, PBKDF2, AES
│   ├── envelope.js     # Package format (v1.1)
│   └── password.js     # Password generator + strength meter
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   └── USAGE.md
├── Dockerfile
├── docker-compose.yml
└── nginx.conf
```

## Why This is Better Than Alternatives

| Method | Security | Recipient Friction |
|---|---|---|
| **Email plaintext** | ❌ Terrible | Zero |
| **Slack message** | ❌ Poor (logged forever) | Zero |
| **1Password share link**  | ✅ Good | Needs 1Password account |
| **PGP encryption** | ✅ Excellent | Needs GPG setup + key exchange |
| **This tool — Password mode**  | **✅ Strong** | **Just a browser + password** |

## Troubleshooting

### Key Length Error During Decryption
If you see "secretKey expected Uint8Array of length 2400, got length=1088", the private key file is invalid or corrupted. This can happen if:
- The key file was generated with a different algorithm
- The key file was truncated during download
- You're using a public key instead of a private key

**Solution**: Re-generate a new keypair and download fresh key files.

### "Decryption failed" Error
- Verify you're using the correct private key (not public key) for keypair mode
- Verify you're entering the correct password for password mode
- Ensure the encrypted file hasn't been modified
- Check that the encrypted file is a valid `.pqenc.json`

### "Password must be at least 8 characters" Error
- Use the **🎲 Generate** button for a strong 24-character password
- Or type your own password (minimum 8 characters, but 12+ recommended)



