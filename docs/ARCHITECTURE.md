# PQC File Encryptor - Architecture

## Overview

A browser-based file encryption system with dual-mode support: post-quantum keypair encryption (ML-KEM-768) and password-based encryption (PBKDF2-SHA256). All encryption/decryption happens client-side — no data is ever transmitted to a server.

## Project Structure

```
files_Encryption/
├── index.html          # Main UI
├── styles.css          # Light/dark theme styles
├── app.js              # Application logic
├── lib/
│   ├── utils.js        # Base64, file I/O, validation, password utilities
│   ├── crypto.js       # ML-KEM-768, PBKDF2, AES-256-GCM, HKDF
│   ├── envelope.js     # Package format (v1.1, dual-mode)
│   └── password.js     # Password generator + strength meter
├── docs/               # Documentation
├── nginx.conf          # Nginx security headers
├── Dockerfile          # Container image
└── docker-compose.yml  # Local dev setup
```

## Security Architecture

### Key Generation (Keypair Mode)
- Uses `@noble/post-quantum` library for ML-KEM-768 key encapsulation
- Generates public/private key pair in browser memory
- Keys are NEVER stored — user must download and manage them

### Password Derivation (Password Mode)
- Uses WebCrypto PBKDF2-SHA256 with 600,000 iterations
- 16-byte random salt generated per encryption operation
- Salt and iterations stored in envelope for decryption
- Derived KEK is non-extractable, scoped to AES-KW operations only

### Encryption Flow (Keypair Mode)
1. Generate random 256-bit Data Encryption Key (DEK)
2. Encrypt file content with AES-256-GCM using DEK
3. Encapsulate DEK with ML-KEM-768 using recipient's public key
4. Wrap DEK with AES-256-KW for additional security
5. Package everything in JSON envelope

### Encryption Flow (Password Mode)
1. Generate random 256-bit Data Encryption Key (DEK)
2. Encrypt file content with AES-256-GCM using DEK
3. Derive KEK from password using PBKDF2-SHA256 (600K iterations + random salt)
4. Wrap DEK with AES-256-KW
5. Package everything in JSON envelope (includes salt + iterations)

### Key Management
- Keys stored as JSON files with base64-encoded key material
- User downloads and saves keys manually
- Private key required for decryption (keypair mode)
- Public key required for encryption (keypair mode)
- Password required for encryption/decryption (password mode)

## UI Components

### Key Management Section
- Generate new keypair
- Download public/private keys
- Import existing keys
- Reset/clear keys from memory
- Hidden when password mode is active

### Mode Toggles
- **Encrypt section**: Switch between Keypair and Password mode
- **Decrypt section**: Switch between Keypair and Password mode
- Each section's mode is independent

### Encrypt Section
- Mode toggle: Keypair / Password
- Keypair mode: Select .txt or .env files, encrypt with public key
- Password mode: Enter or generate password, select file, encrypt

### Decrypt Section
- Mode toggle: Keypair / Password
- Keypair mode: Select .pqenc.json, decrypt with private key
- Password mode: Select .pqenc.json, enter password, decrypt

### Password UI (Password Mode)
- Password input field with show/hide toggle
- "Generate" button — produces 24-char cryptographically random password
- Strength meter — real-time entropy estimation (Very Weak → Very Strong)

## Error Handling

### Key Validation
- Private keys validated for correct length (2400 bytes for ML-KEM-768)
- Invalid keys produce clear error messages instead of cryptic library errors

### Password Validation
- Minimum 8 characters required
- Strength meter warns on weak passwords
- Generated passwords always meet "Very Strong" threshold

### Common Errors
- "secretKey expected Uint8Array of length 2400" — Wrong key type or corrupted key file
- "Decryption failed" — Authentication tag mismatch, wrong key, or wrong password
- "Password must be at least 8 characters" — Password too short for encryption

## Envelope Format

### Version 1.0 (Keypair Only)
```json
{
  "version": "1.0",
  "type": "pq-envelope",
  "kem": "ML-KEM-768",
  "kdf": "HKDF-SHA-256",
  "aead": "AES-256-GCM",
  "nonce": "...",
  "kemCiphertext": "...",
  "wrappedDek": "...",
  "ciphertext": "...",
  "tag": "...",
  "originalName": "...",
  "originalExtension": "...",
  "originalSize": 0
}
```

### Version 1.1 (Dual Mode)
Adds `mode` field. Keypair mode: identical to v1.0 plus `"mode": "KEYPAIR"`. Password mode:
```json
{
  "version": "1.1",
  "type": "pq-envelope",
  "mode": "PASSWORD",
  "kem": "NONE",
  "kdf": "PBKDF2-SHA-256",
  "aead": "AES-256-GCM",
  "nonce": "...",
  "kemCiphertext": "",
  "salt": "...",
  "iterations": 600000,
  "wrappedDek": "...",
  "ciphertext": "...",
  "tag": "...",
  "originalName": "...",
  "originalExtension": "...",
  "originalSize": 0
}
```
