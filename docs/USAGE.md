# Usage Guide

## Quick Start

### Keypair Mode

#### 1. Generate Keys
1. Open the application in a browser
2. Click **"Generate Keypair"**
3. Download both Public Key and Private Key files

#### 2. Share Public Key
Send the public key file to anyone who needs to encrypt files for you.

#### 3. Encrypt a File
1. Import recipient's Public Key
2. Click **"Choose File"** and select a .txt or .env file
3. Click **"Encrypt File"**
4. Download the encrypted .pqenc.json file

#### 4. Decrypt a File
1. Import your Private Key
2. Click **"Choose File"** and select a .pqenc.json file
3. Click **"Decrypt File"**
4. Download the original file

### Password Mode

#### 1. Encrypt a File
1. In the Encrypt section, switch the mode toggle from **🔑 Keypair** to **🔒 Password**
2. Click **🎲 Generate** to create a strong 24-character password (or type your own)
3. Click **"Choose File"** and select a .txt or .env file
4. Click **"Encrypt File"**
5. Download the encrypted .pqenc.json file

#### 2. Share the Encrypted File
- Send the `.pqenc.json` file via any channel (email, Slack, cloud storage)
- Share the password via a **separate channel** (Signal, WhatsApp, verbal)
- Never send the file and password through the same channel

#### 3. Decrypt a File
1. Open the application in a browser
2. In the Decrypt section, switch the mode toggle from **🔑 Keypair** to **🔒 Password**
3. Click **"Choose File"** and select the .pqenc.json file
4. Enter the password
5. Click **"Decrypt File"**
6. Download the original file

## File Format Support

### Input Files (Encryption)
- `.txt` — Plain text files
- `.env` — Environment files
- Max size: 10MB

### Output Files (Encrypted)
- `.pqenc.json` — Encrypted package format (works for both modes)

## Key Management

### Key File Format
Keys are stored as JSON with base64-encoded key material:

```json
{
  "version": "1.0",
  "type": "mlkem-public-key",
  "algorithm": "ML-KEM-768",
  "encoding": "base64",
  "created": "2026-04-05T12:00:00Z",
  "keyData": "base64-encoded-key-bytes"
}
```

### Best Practices
1. Store private key securely (password manager, encrypted drive)
2. Never share private key
3. Keep backup of private key
4. Verify key fingerprint before use
5. For password mode: use the generated password or a passphrase of 12+ characters

## Password Mode Tips

### Using the Password Generator
- Click **🎲 Generate** to create a 24-character random password
- This gives ~158 bits of entropy — effectively uncrackable
- The password is shown in the input field so you can copy it

### Password Strength Meter
- Updates in real-time as you type
- Shows entropy bits and strength label
- Colors: Red (Very Weak) → Orange (Weak) → Yellow (Fair) → Green (Strong) → Dark Green (Very Strong)
- Aim for at least "Strong" (80+ bits) if typing your own password

### Sharing Passwords Safely
- ✅ Signal, WhatsApp, Telegram (encrypted messaging)
- ✅ Verbal (in person or phone call)
- ✅ Password manager shared vault
- ❌ Email (same channel as the encrypted file)
- ❌ Slack/Teams (logged and searchable)
- ❌ Sticky notes

## Troubleshooting

### "Public key required" error
- Import a public key before encrypting (keypair mode)
- Or switch to Password mode if you don't have keys

### "Private key required" error
- Import a private key before decrypting (keypair mode)
- Or switch to Password mode if the file was encrypted with a password

### "Decryption failed" error
- **Keypair mode**: Wrong private key for this encrypted file, or file was modified/corrupted
- **Password mode**: Wrong password entered — check for typos, extra spaces, or case sensitivity
- File is not a valid .pqenc.json

### Key generation fails
- Use modern browser (Chrome, Edge, Firefox)
- Ensure WebCrypto API is available

### "secretKey expected Uint8Array of length 2400" error
This error indicates the private key is invalid or corrupted. Common causes:
- Using a public key instead of a private key
- Key file was truncated during download
- Key was generated with a different algorithm

**Solution**:
1. Re-generate a new keypair
2. Download fresh key files (don't copy/paste)
3. Ensure you're importing the private key file for decryption

### "Password must be at least 8 characters" error
- Use the **🎲 Generate** button for a strong password
- Or type a longer password (12+ characters recommended)

### Envelope version error
- If you see "Unsupported package version", your tool may be outdated
- Version 1.0 and 1.1 envelopes are both supported in the current release
