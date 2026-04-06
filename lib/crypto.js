/**
 * crypto.js
 * Cryptographic core for the PQC File Encryptor.
 *
 * Algorithm stack (LOCKED):
 *   Key Encapsulation : ML-KEM-768  (NIST FIPS 203 Level 3)
 *   Key Derivation    : HKDF-SHA-256
 *   DEK Wrapping      : AES-256-KW
 *   Payload Cipher    : AES-256-GCM  (authenticated, 128-bit tag, 96-bit nonce)
 *   Randomness        : crypto.getRandomValues()  (Web Crypto)
 *
 * No fallback algorithms.  All errors fail closed.
 *
 * Dependencies:
 *   @noble/post-quantum  — pure-JS ML-KEM-768 (no WASM required)
 *   Web Crypto API       — HKDF, AES-KW, AES-GCM
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { bytesToBase64, base64ToBytes } from './utils.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const ALGORITHM_NAME = 'ML-KEM-768';
const KEY_VERSION    = '1.0';

/** HKDF context string — binds derived keys to this application. */
const HKDF_INFO = new TextEncoder().encode('PQC-File-Encryptor-KEK-v1');

/** HKDF salt — 32 zero bytes (no extractable randomness needed; shared secret already provides entropy). */
const HKDF_SALT = new Uint8Array(32);

// ─── Key Pair Generation ──────────────────────────────────────────────────────

/**
 * Generate a fresh ML-KEM-768 key pair.
 *
 * Randomness is sourced internally by @noble/post-quantum via crypto.getRandomValues().
 *
 * @returns {{ publicKey: Uint8Array, privateKey: Uint8Array }}
 */
export function generateKeyPair() {
  let result;
  try {
    result = ml_kem768.keygen();
  } catch (err) {
    throw new Error(`ML-KEM-768 key generation failed: ${err.message}`);
  }

  const { publicKey, secretKey } = result;

  console.log('[KEYGEN] publicKey length:', publicKey.length);
  console.log('[KEYGEN] secretKey length:', secretKey.length);

  if (!(publicKey instanceof Uint8Array) || publicKey.length === 0) {
    throw new Error('ML-KEM-768 keygen returned an invalid public key.');
  }
  if (!(secretKey instanceof Uint8Array) || secretKey.length === 0) {
    throw new Error('ML-KEM-768 keygen returned an invalid secret key.');
  }

  return { publicKey, privateKey: secretKey };
}

// ─── Key Serialization ────────────────────────────────────────────────────────

/**
 * Serialize a public key to the versioned JSON key-file format.
 *
 * @param {Uint8Array} publicKey
 * @returns {string}  Pretty-printed JSON string
 */
export function serializePublicKey(publicKey) {
  _assertUint8Array('publicKey', publicKey);

  return JSON.stringify(
    {
      version:   KEY_VERSION,
      type:      'mlkem-public-key',
      algorithm: ALGORITHM_NAME,
      encoding:  'base64',
      created:   new Date().toISOString(),
      keyData:   bytesToBase64(publicKey),
    },
    null,
    2
  );
}

/**
 * Serialize a private key to the versioned JSON key-file format.
 *
 * @param {Uint8Array} privateKey
 * @returns {string}  Pretty-printed JSON string
 */
export function serializePrivateKey(privateKey) {
  _assertUint8Array('privateKey', privateKey);

  return JSON.stringify(
    {
      version:   KEY_VERSION,
      type:      'mlkem-private-key',
      algorithm: ALGORITHM_NAME,
      encoding:  'base64',
      created:   new Date().toISOString(),
      keyData:   bytesToBase64(privateKey),
    },
    null,
    2
  );
}

// ─── Key Parsing + Validation ─────────────────────────────────────────────────

/**
 * Parse and validate a public-key JSON string.
 *
 * Rejects: wrong version, wrong type, wrong algorithm, malformed base64, empty keyData.
 *
 * @param {string} jsonText
 * @returns {Uint8Array}  Raw public key bytes
 * @throws {Error}  Descriptive error safe to show the user
 */
export function parsePublicKey(jsonText) {
  const obj = _safeParseKeyJSON(jsonText);
  _validateKeyFile(obj, 'mlkem-public-key');
  return base64ToBytes(obj.keyData);
}

/**
 * Parse and validate a private-key JSON string.
 *
 * Rejects: wrong version, wrong type, wrong algorithm, malformed base64, empty keyData.
 *
 * @param {string} jsonText
 * @returns {Uint8Array}  Raw private key bytes
 * @throws {Error}  Descriptive error safe to show the user
 */
export function parsePrivateKey(jsonText) {
  const obj = _safeParseKeyJSON(jsonText);
  _validateKeyFile(obj, 'mlkem-private-key');
  return base64ToBytes(obj.keyData);
}

// ─── ML-KEM Operations ────────────────────────────────────────────────────────

/**
 * ML-KEM-768 encapsulate.
 *
 * Generates a fresh shared secret and the KEM ciphertext that the recipient
 * must decapsulate (with their private key) to recover the same shared secret.
 *
 * @param {Uint8Array} publicKey  - Recipient's ML-KEM-768 public key
 * @returns {{ kemCiphertext: Uint8Array, sharedSecret: Uint8Array }}
 * @throws {Error}  If the public key is rejected by the library
 */
export function encapsulate(publicKey) {
  _assertUint8Array('publicKey', publicKey);

  console.log('[ENCAPSULATE] publicKey length:', publicKey.length);

  let result;
  try {
    result = ml_kem768.encapsulate(publicKey);
  } catch (err) {
    console.error('[ENCAPSULATE] Error:', err);
    throw new Error(
      'ML-KEM-768 encapsulation failed: ' + err.message + '. ' +
      'The public key file may be corrupted.'
    );
  }

  const { cipherText, sharedSecret } = result;

  console.log('[ENCAPSULATE] cipherText length:', cipherText.length);
  console.log('[ENCAPSULATE] sharedSecret length:', sharedSecret.length);

  if (!(cipherText    instanceof Uint8Array) || cipherText.length    === 0) throw new Error('ML-KEM encapsulate returned an empty ciphertext.');
  if (!(sharedSecret  instanceof Uint8Array) || sharedSecret.length  === 0) throw new Error('ML-KEM encapsulate returned an empty shared secret.');

  return { kemCiphertext: cipherText, sharedSecret };
}

/**
 * ML-KEM-768 decapsulate.
 *
 * Recovers the shared secret from a KEM ciphertext using the private key.
 * Fails closed — any error (wrong key, corrupted ciphertext) becomes a
 * generic decryption failure message.
 *
 * @param {Uint8Array} kemCiphertext  - KEM ciphertext from the envelope
 * @param {Uint8Array} privateKey     - Recipient's ML-KEM-768 private key
 * @returns {Uint8Array}  Shared secret (32 bytes)
 * @throws {Error}
 */
export function decapsulate(kemCiphertext, privateKey) {
  _assertUint8Array('kemCiphertext', kemCiphertext);
  _assertUint8Array('privateKey',   privateKey);

  console.log('[DECAPSULATE] kemCiphertext length:', kemCiphertext.length);
  console.log('[DECAPSULATE] privateKey length:', privateKey.length);

  let sharedSecret;
  try {
    sharedSecret = ml_kem768.decapsulate(kemCiphertext, privateKey);
  } catch (err) {
    console.error('[DECAPSULATE] Error:', err);
    throw new Error(
      'ML-KEM-768 decapsulation failed: ' + err.message + '. ' +
      'The private key does not match the one used to encrypt this file, ' +
      'or the encrypted package is corrupted.'
    );
  }

  if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length === 0) {
    throw new Error('ML-KEM decapsulate returned an empty shared secret.');
  }

  return sharedSecret;
}

// ─── HKDF Key Derivation ──────────────────────────────────────────────────────

/**
 * Derive the Key Encryption Key (KEK) from the ML-KEM shared secret
 * using HKDF-SHA-256.
 *
 * KEK is a non-extractable AES-256 key scoped to AES-KW operations only.
 *
 * @param {Uint8Array} sharedSecret  - 32-byte ML-KEM shared secret
 * @returns {Promise<CryptoKey>}     - AES-256-KW key for wrapKey / unwrapKey
 */
export async function deriveKEK(sharedSecret) {
  _assertUint8Array('sharedSecret', sharedSecret);

  // Import the raw shared secret as an HKDF base key
  let baseKey;
  try {
    baseKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,           // not extractable
      ['deriveKey']
    );
  } catch (err) {
    throw new Error(`HKDF importKey failed: ${err.message}`);
  }

  // Derive a 256-bit AES-KW key
  try {
    return await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: HKDF_SALT,
        info: HKDF_INFO,
      },
      baseKey,
      { name: 'AES-KW', length: 256 },
      false,            // not extractable
      ['wrapKey', 'unwrapKey']
    );
  } catch (err) {
    throw new Error(`HKDF deriveKey failed: ${err.message}`);
  }
}

// ─── Password-Based Key Derivation ──────────────────────────────────────

/**
 * Derive a 256-bit AES-KW key from a password using PBKDF2-SHA256.
 *
 * Uses 600,000 iterations (OWASP 2026 minimum for HMAC-SHA-256).
 * Returns a non-extractable AES-KW CryptoKey scoped to wrapKey/unwrapKey.
 *
 * @param {Uint8Array} password   - UTF-8 encoded password bytes
 * @param {Uint8Array} salt       - 16-byte random salt
 * @param {number}     iterations - PBKDF2 iteration count (default: 600000)
 * @returns {Promise<CryptoKey>}  - AES-256-KW key
 */
export async function deriveKEKFromPassword(password, salt, iterations = 600_000) {
  _assertUint8Array('password', password);
  _assertUint8Array('salt', salt);

  if (typeof iterations !== 'number' || iterations < 100_000) {
    throw new Error('PBKDF2 iterations must be at least 100,000.');
  }

  const baseKey = await crypto.subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations,
    },
    baseKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

// ─── AES-KW DEK Wrapping ─────────────────────────────────────────────────────

/**
 * Generate a random 256-bit Data Encryption Key (DEK) for AES-256-GCM.
 *
 * The key is extractable so it can be wrapped by AES-KW.
 *
 * @returns {Promise<CryptoKey>}
 */
export function generateDEK() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,             // extractable — needed for wrapKey
    ['encrypt', 'decrypt']
  );
}

/**
 * Wrap the DEK with the KEK using RFC 3394 AES-256-KW.
 *
 * @param {CryptoKey} dek  - Extractable AES-GCM key to wrap
 * @param {CryptoKey} kek  - AES-KW key derived from HKDF
 * @returns {Promise<Uint8Array>}  Wrapped DEK bytes (40 bytes for a 256-bit key)
 */
export async function wrapDEK(dek, kek) {
  let wrapped;
  try {
    wrapped = await crypto.subtle.wrapKey('raw', dek, kek, 'AES-KW');
  } catch (err) {
    throw new Error(`AES-KW wrapKey failed: ${err.message}`);
  }
  return new Uint8Array(wrapped);
}

/**
 * Unwrap a wrapped DEK using AES-256-KW.
 *
 * Returns a non-extractable AES-GCM CryptoKey.
 * Fails closed if the wrapped DEK is corrupted or the wrong KEK is used.
 *
 * @param {Uint8Array} wrappedDekBytes
 * @param {CryptoKey}  kek
 * @returns {Promise<CryptoKey>}  Non-extractable AES-256-GCM key for decrypt
 */
export async function unwrapDEK(wrappedDekBytes, kek) {
  _assertUint8Array('wrappedDekBytes', wrappedDekBytes);

  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      wrappedDekBytes,
      kek,
      'AES-KW',
      { name: 'AES-GCM', length: 256 },
      false,           // not extractable after unwrapping
      ['decrypt']
    );
  } catch {
    // Absorb internal error details — they should not be leaked.
    throw new Error(
      'Failed to unwrap the data encryption key. ' +
      'The private key does not match this encrypted package, ' +
      'or the package has been tampered with.'
    );
  }
}

// ─── AES-256-GCM ──────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext using AES-256-GCM with a random 96-bit nonce.
 *
 * The authentication tag (128 bits) is separated from the ciphertext so that
 * both can be stored as independent base64 fields in the envelope.
 *
 * WebCrypto's AES-GCM returns  ciphertext ∥ tag  as a single ArrayBuffer.
 * We split off the last 16 bytes as the tag.
 *
 * @param {Uint8Array} plaintext
 * @param {CryptoKey}  dek   - AES-256-GCM key
 * @param {Uint8Array} aad   - Additional authenticated data (from buildAAD)
 * @returns {Promise<{ ciphertext: Uint8Array, tag: Uint8Array, nonce: Uint8Array }>}
 */
export async function encryptAESGCM(plaintext, dek, aad) {
  _assertUint8Array('plaintext', plaintext);
  _assertUint8Array('aad',       aad);

  // 96-bit random nonce — never reuse with the same key
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  let encryptedBuffer;
  try {
    encryptedBuffer = await crypto.subtle.encrypt(
      {
        name:           'AES-GCM',
        iv:             nonce,
        additionalData: aad,
        tagLength:      128,
      },
      dek,
      plaintext
    );
  } catch (err) {
    throw new Error(`AES-256-GCM encryption failed: ${err.message}`);
  }

  // Split ciphertext and tag
  const encArr    = new Uint8Array(encryptedBuffer);
  const ciphertext = encArr.slice(0, encArr.length - 16);
  const tag        = encArr.slice(encArr.length - 16);

  return { ciphertext, tag, nonce };
}

/**
 * Decrypt a ciphertext and verify its authentication tag using AES-256-GCM.
 *
 * The caller must reconstruct the same AAD that was used during encryption —
 * any mismatch (tampered metadata or ciphertext) will cause this to throw.
 *
 * @param {Uint8Array} ciphertext  - Encrypted bytes (may be empty for an empty file)
 * @param {Uint8Array} tag         - 16-byte GCM authentication tag
 * @param {CryptoKey}  dek         - AES-256-GCM key
 * @param {Uint8Array} nonce       - 12-byte nonce stored in the envelope
 * @param {Uint8Array} aad         - Must match the AAD used during encryption exactly
 * @returns {Promise<Uint8Array>}  Recovered plaintext
 * @throws {Error}  Fails closed on any authentication or decryption error
 */
export async function decryptAESGCM(ciphertext, tag, dek, nonce, aad) {
  _assertUint8Array('ciphertext', ciphertext);
  _assertUint8Array('tag',        tag);
  _assertUint8Array('nonce',      nonce);
  _assertUint8Array('aad',        aad);

  if (tag.length !== 16) {
    throw new Error(`GCM authentication tag must be 16 bytes, got ${tag.length}.`);
  }
  if (nonce.length !== 12) {
    throw new Error(`GCM nonce must be 12 bytes, got ${nonce.length}.`);
  }

  // WebCrypto expects ciphertext ∥ tag concatenated
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  let decryptedBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt(
      {
        name:           'AES-GCM',
        iv:             nonce,
        additionalData: aad,
        tagLength:      128,
      },
      dek,
      combined
    );
  } catch {
    // Do NOT surface the browser's internal error — it may be an oracle.
    throw new Error(
      'Decryption failed: authentication tag mismatch. ' +
      'The encrypted package has been tampered with, is corrupted, ' +
      'or the wrong private key was used.'
    );
  }

  return new Uint8Array(decryptedBuffer);
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Parse the raw text of a key file as JSON, with a friendly error message.
 * @param {string} text
 * @returns {object}
 */
function _safeParseKeyJSON(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    throw new Error('Key file is empty.');
  }

  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error(
      'Invalid JSON: the selected file is not a valid key file. ' +
      'Make sure you chose a .mlkem.json key file.'
    );
  }

  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('Key file must be a JSON object.');
  }

  return obj;
}

/**
 * Validate the header fields of a parsed key-file object.
 * Throws a descriptive, user-safe Error on any mismatch.
 *
 * @param {object} obj
 * @param {'mlkem-public-key' | 'mlkem-private-key'} expectedType
 */
function _validateKeyFile(obj, expectedType) {
  // Version
  if (obj.version !== KEY_VERSION) {
    throw new Error(
      `Unsupported key version: "${obj.version ?? '(missing)'}". ` +
      `Expected "${KEY_VERSION}".`
    );
  }

  // Type
  if (obj.type !== expectedType) {
    const wantLabel = expectedType === 'mlkem-public-key' ? 'public' : 'private';
    const gotLabel  = obj.type === 'mlkem-public-key'
      ? 'public'
      : obj.type === 'mlkem-private-key'
        ? 'private'
        : `unknown ("${obj.type ?? '(missing)'}")`;

    throw new Error(
      `Wrong key type — expected a ${wantLabel} key but got a ${gotLabel} key. ` +
      'Make sure you are importing the correct key file.'
    );
  }

  // Algorithm
  if (obj.algorithm !== ALGORITHM_NAME) {
    throw new Error(
      `Unsupported algorithm: "${obj.algorithm ?? '(missing)'}". ` +
      `Expected "${ALGORITHM_NAME}".`
    );
  }

  // keyData presence
  if (typeof obj.keyData !== 'string' || obj.keyData.trim() === '') {
    throw new Error('Key file is missing the "keyData" field or it is empty.');
  }

  // keyData decodability + non-empty
  let decoded;
  try {
    decoded = base64ToBytes(obj.keyData);
  } catch {
    throw new Error('Key file contains malformed base64 in the "keyData" field.');
  }

  if (decoded.length === 0) {
    throw new Error('Key file "keyData" decodes to zero bytes — the key is invalid.');
  }
}

/**
 * Assert that a value is a Uint8Array; throws a TypeError otherwise.
 * @param {string} name
 * @param {*}      value
 */
function _assertUint8Array(name, value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(
      `Expected "${name}" to be a Uint8Array, ` +
      `got ${Object.prototype.toString.call(value)}`
    );
  }
}
