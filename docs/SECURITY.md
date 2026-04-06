# Security Model

## Cryptographic Algorithms

### Keypair Mode

#### ML-KEM-768 (Key Encapsulation)
- NIST FIPS 203 Level 3 (AES-192 equivalent security)
- Lattice-based post-quantum algorithm
- Provides protection against quantum computers

#### HKDF-SHA-256 (Key Derivation)
- Derives Key Encryption Key (KEK) from ML-KEM shared secret
- Binds derived keys to this application

### Password Mode

#### PBKDF2-SHA256 (Key Derivation)
- 600,000 iterations (OWASP 2026 minimum for HMAC-SHA-256)
- ~200ms derivation time on typical hardware
- Per-envelope random 16-byte salt (prevents rainbow table attacks)
- Iteration count stored in envelope for future-proofing

**Why PBKDF2?** It is the only password-based KDF natively available in the WebCrypto API. While Argon2id is the 2026 gold standard, it requires external libraries. PBKDF2 with 600K iterations provides adequate security when paired with strong generated passwords (~158 bits entropy).

### Shared (Both Modes)

#### AES-256-GCM (Payload Encryption)
- Authenticated encryption with 128-bit tag
- 96-bit random nonce per encryption
- Additional Authenticated Data (AAD) for metadata protection

#### AES-256-KW (Key Wrapping)
- RFC 3394 compliant key wrapping
- Protects the DEK in the encrypted package

## Security Properties

### Confidentiality
- Files encrypted with AES-256-GCM
- Keypair mode: DEK protected by ML-KEM encapsulation
- Password mode: DEK protected by PBKDF2-derived KEK

### Integrity
- AES-GCM authentication tag prevents tampering
- AAD binds metadata to ciphertext

### Forward Secrecy
- New DEK generated for each file
- Compromised key doesn't expose past files

### Post-Quantum Security
- Keypair mode: ML-KEM provides quantum-resistant key encapsulation
- Password mode: AES-256-GCM is quantum-resistant at 256-bit key size

## Threat Model

### Protected Against
- Network interception (client-side only)
- Quantum computer attacks (ML-KEM in keypair mode)
- File tampering (authentication tag)
- Rainbow table attacks (per-envelope salt in password mode)

### User Responsibilities
- **Keypair mode**: Securely store private key, never share it
- **Password mode**: Use generated passwords or strong passphrases (12+ chars), share passwords via a separate channel from the encrypted file
- Verify key fingerprints before use (keypair mode)

## Limitations

- No key recovery (private key or password loss = permanent data loss)
- No recipient verification
- Browser-based (dependent on WebCrypto API)
- PBKDF2 is not memory-hard — GPU attacks are feasible against weak passwords. Mitigated by the built-in password generator producing ~158 bits of entropy.

## Envelope Format

### Version 1.0 (Keypair Only)
Legacy format. Still fully supported for backward compatibility.

### Version 1.1 (Dual Mode)
Adds `mode` field (`KEYPAIR` or `PASSWORD`). Password mode envelopes include `salt` and `iterations` fields. Keypair mode envelopes remain structurally identical to v1.0.
