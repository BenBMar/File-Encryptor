/**
 * envelope.js
 * Envelope serialization / deserialization for the PQC encrypted package format.
 *
 * Packed format (JSON):
 * {
 *   version, type, mode, kem, kdf, aead,
 *   nonce, kemCiphertext, wrappedDek, ciphertext, tag,
 *   salt, iterations,          ← password mode only
 *   originalName, originalExtension, originalSize
 * }
 *
 * All binary fields are base64-encoded.
 * Metadata fields (originalName, originalExtension, originalSize)
 * are authenticated via AES-GCM AAD — see buildAAD().
 */

import { bytesToBase64, base64ToBytes } from './utils.js';

// ─── Constants ────────────────────────────────────────────────────────────────

export const ENVELOPE_VERSION = '1.1';
export const ENVELOPE_MODE_KEYPAIR = 'KEYPAIR';
export const ENVELOPE_MODE_PASSWORD = 'PASSWORD';

const ENVELOPE_TYPE   = 'pq-envelope';
const ENVELOPE_AEAD   = 'AES-256-GCM';

/** Supported envelope versions for backward compatibility. */
const SUPPORTED_VERSIONS = ['1.0', '1.1'];

/** Constants for KEYPAIR mode. */
const KEYPAIR_KEM = 'ML-KEM-768';
const KEYPAIR_KDF = 'HKDF-SHA-256';

/** Constants for PASSWORD mode. */
const PASSWORD_KEM = 'NONE';
const PASSWORD_KDF = 'PBKDF2-SHA-256';

/** Fields always required regardless of mode. */
const ALWAYS_REQUIRED = [
  'version',
  'type',
  'nonce',
  'wrappedDek',
  'ciphertext',
  'tag',
  'originalName',
  'originalExtension',
  'originalSize',
];

/** Fields required only in KEYPAIR mode. */
const KEYPAIR_REQUIRED = ['kemCiphertext'];

/** Fields required only in PASSWORD mode. */
const PASSWORD_REQUIRED = ['salt', 'iterations'];

/** Fields whose values must be valid base64 (mode-independent). */
const BASE64_FIELDS = ['nonce', 'wrappedDek', 'ciphertext', 'tag'];

/** Fields that must decode to at least 1 byte. */
const NONEMPTY_BASE64_FIELDS = ['nonce', 'wrappedDek', 'tag'];

// ─── AAD Construction ─────────────────────────────────────────────────────────

/**
 * Build the Additional Authenticated Data (AAD) for AES-GCM.
 *
 * @param {string} originalName       - Full original filename
 * @param {string} originalExtension  - File extension
 * @param {number} originalSize       - File size in bytes
 * @returns {Uint8Array}
 */
export function buildAAD(originalName, originalExtension, originalSize) {
  const meta = `pqe-aad-v1|${originalName}|${originalExtension}|${String(originalSize)}`;
  return new TextEncoder().encode(meta);
}

// ─── Packing ──────────────────────────────────────────────────────────────────

/**
 * Serialize all encrypted components into a pretty-printed JSON string.
 *
 * @param {object} params
 * @param {Uint8Array} params.kemCiphertext   - ML-KEM ciphertext (KEYPAIR mode, may be null for PASSWORD)
 * @param {Uint8Array} params.wrappedDek      - AES-KW wrapped Data Encryption Key
 * @param {Uint8Array} params.ciphertext      - AES-GCM encrypted file bytes
 * @param {Uint8Array} params.tag             - AES-GCM 128-bit authentication tag
 * @param {Uint8Array} params.nonce           - AES-GCM 96-bit random nonce
 * @param {string}     params.originalName      - Original filename
 * @param {string}     params.originalExtension - Original file extension
 * @param {number}     params.originalSize      - Original file size in bytes
 * @param {string}     [params.mode='KEYPAIR']  - Encryption mode
 * @param {Uint8Array} [params.salt]            - PBKDF2 salt (PASSWORD mode)
 * @param {number}     [params.iterations]      - PBKDF2 iterations (PASSWORD mode)
 * @returns {string} JSON string
 */
export function packEnvelope({
  kemCiphertext,
  wrappedDek,
  ciphertext,
  tag,
  nonce,
  originalName,
  originalExtension,
  originalSize,
  mode = ENVELOPE_MODE_KEYPAIR,
  salt,
  iterations,
}) {
  _assertUint8Array('wrappedDek', wrappedDek);
  _assertUint8Array('ciphertext', ciphertext);
  _assertUint8Array('tag', tag);
  _assertUint8Array('nonce', nonce);

  if (typeof originalName !== 'string' || originalName.length === 0) {
    throw new TypeError('packEnvelope: originalName must be a non-empty string');
  }
  if (typeof originalExtension !== 'string') {
    throw new TypeError('packEnvelope: originalExtension must be a string');
  }
  if (typeof originalSize !== 'number' || !Number.isFinite(originalSize) || originalSize < 0) {
    throw new TypeError('packEnvelope: originalSize must be a non-negative finite number');
  }

  if (mode !== ENVELOPE_MODE_KEYPAIR && mode !== ENVELOPE_MODE_PASSWORD) {
    throw new TypeError(`packEnvelope: invalid mode "${mode}"`);
  }

  // Build mode-specific fields
  let kem, kdf, kemCiphertextB64;

  if (mode === ENVELOPE_MODE_PASSWORD) {
    if (!salt || !(salt instanceof Uint8Array)) {
      throw new TypeError('packEnvelope: salt is required for PASSWORD mode');
    }
    if (typeof iterations !== 'number' || iterations < 100_000) {
      throw new TypeError('packEnvelope: iterations must be >= 100,000 for PASSWORD mode');
    }
    kem = PASSWORD_KEM;
    kdf = PASSWORD_KDF;
    kemCiphertextB64 = '';
  } else {
    // KEYPAIR mode
    if (!kemCiphertext || !(kemCiphertext instanceof Uint8Array)) {
      throw new TypeError('packEnvelope: kemCiphertext is required for KEYPAIR mode');
    }
    kem = KEYPAIR_KEM;
    kdf = KEYPAIR_KDF;
    kemCiphertextB64 = bytesToBase64(kemCiphertext);
  }

  const envelope = {
    version:           ENVELOPE_VERSION,
    type:              ENVELOPE_TYPE,
    mode,
    kem,
    kdf,
    aead:              ENVELOPE_AEAD,
    nonce:             bytesToBase64(nonce),
    kemCiphertext:     kemCiphertextB64,
    wrappedDek:        bytesToBase64(wrappedDek),
    ciphertext:        bytesToBase64(ciphertext),
    tag:               bytesToBase64(tag),
    originalName,
    originalExtension,
    originalSize,
  };

  if (mode === ENVELOPE_MODE_PASSWORD) {
    envelope.salt = bytesToBase64(salt);
    envelope.iterations = iterations;
  }

  return JSON.stringify(envelope, null, 2);
}

// ─── Unpacking ────────────────────────────────────────────────────────────────

/**
 * Parse and strictly validate a .pqenc.json text, then return all fields in
 * decoded form.  Supports both v1.0 (KEYPAIR only) and v1.1 (KEYPAIR | PASSWORD).
 *
 * @param {string} jsonText - Raw text content of a .pqenc.json file
 * @returns {{
 *   mode:              string,
 *   nonce:             Uint8Array,
 *   kemCiphertext:     Uint8Array,
 *   wrappedDek:        Uint8Array,
 *   ciphertext:        Uint8Array,
 *   tag:               Uint8Array,
 *   salt:              Uint8Array|null,
 *   iterations:        number|null,
 *   originalName:      string,
 *   originalExtension: string,
 *   originalSize:      number,
 * }}
 */
export function unpackEnvelope(jsonText) {
  // ── 1. JSON parse ──────────────────────────────────────────────────────────
  if (typeof jsonText !== 'string' || jsonText.trim() === '') {
    throw new Error('Encrypted package is empty or not a text file.');
  }

  let obj;
  try {
    obj = JSON.parse(jsonText);
  } catch {
    throw new Error(
      'Invalid JSON: the file does not appear to be a valid encrypted package. ' +
      'Make sure you selected a .pqenc.json file.'
    );
  }

  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('Encrypted package must be a JSON object, not an array or primitive.');
  }

  // ── 2. Version check ───────────────────────────────────────────────────────
  if (!SUPPORTED_VERSIONS.includes(obj.version)) {
    throw new Error(
      `Unsupported package version: "${obj.version}". ` +
      `This application supports versions ${SUPPORTED_VERSIONS.join(', ')} only.`
    );
  }

  if (obj.type !== ENVELOPE_TYPE) {
    throw new Error(
      `Wrong package type: "${obj.type}". ` +
      'This file is not a PQ-encrypted package.'
    );
  }

  if (obj.aead !== ENVELOPE_AEAD) {
    throw new Error(
      `Unsupported AEAD scheme: "${obj.aead}". Expected "${ENVELOPE_AEAD}".`
    );
  }

  // ── 3. Determine mode ──────────────────────────────────────────────────────
  // v1.0 has no 'mode' field — default to KEYPAIR
  const mode = obj.mode || ENVELOPE_MODE_KEYPAIR;

  if (mode !== ENVELOPE_MODE_KEYPAIR && mode !== ENVELOPE_MODE_PASSWORD) {
    throw new Error(`Unsupported encryption mode: "${mode}".`);
  }

  // ── 4. Required field presence (mode-dependent) ────────────────────────────
  const requiredFields = [...ALWAYS_REQUIRED];
  if (mode === ENVELOPE_MODE_KEYPAIR) {
    requiredFields.push(...KEYPAIR_REQUIRED);
  } else {
    requiredFields.push(...PASSWORD_REQUIRED);
  }

  for (const field of requiredFields) {
    if (obj[field] === undefined || obj[field] === null) {
      throw new Error(
        `Malformed encrypted package: missing required field "${field}". ` +
        'The file may be truncated or corrupted.'
      );
    }
  }

  // ── 5. Algorithm checks (mode-dependent) ───────────────────────────────────
  if (mode === ENVELOPE_MODE_KEYPAIR) {
    if (obj.kem !== KEYPAIR_KEM) {
      throw new Error(
        `Unsupported KEM algorithm: "${obj.kem}". Expected "${KEYPAIR_KEM}".`
      );
    }
    if (obj.kdf !== KEYPAIR_KDF) {
      throw new Error(
        `Unsupported KDF: "${obj.kdf}". Expected "${KEYPAIR_KDF}".`
      );
    }
  } else {
    if (obj.kem !== PASSWORD_KEM) {
      throw new Error(
        `Unsupported KEM for password mode: "${obj.kem}". Expected "${PASSWORD_KEM}".`
      );
    }
    if (obj.kdf !== PASSWORD_KDF) {
      throw new Error(
        `Unsupported KDF for password mode: "${obj.kdf}". Expected "${PASSWORD_KDF}".`
      );
    }
  }

  // ── 6. Base64 fields — decode and check ────────────────────────────────────
  const decoded = {};

  for (const field of BASE64_FIELDS) {
    if (typeof obj[field] !== 'string') {
      throw new Error(`Field "${field}" must be a string (base64), got ${typeof obj[field]}.`);
    }

    let bytes;
    try {
      bytes = base64ToBytes(obj[field]);
    } catch {
      throw new Error(
        `Malformed base64 in field "${field}". The package may be corrupted.`
      );
    }

    if (NONEMPTY_BASE64_FIELDS.includes(field) && bytes.length === 0) {
      throw new Error(
        `Field "${field}" decoded to zero bytes. ` +
        'The package is missing required cryptographic material.'
      );
    }

    decoded[field] = bytes;
  }

  // ── 7. Mode-specific field handling ────────────────────────────────────────
  let kemCiphertext = null;
  let saltBytes = null;
  let iterationsVal = null;

  if (mode === ENVELOPE_MODE_KEYPAIR) {
    // Decode kemCiphertext
    if (typeof obj.kemCiphertext !== 'string') {
      throw new Error(`Field "kemCiphertext" must be a string (base64).`);
    }
    try {
      kemCiphertext = base64ToBytes(obj.kemCiphertext);
    } catch {
      throw new Error('Malformed base64 in field "kemCiphertext".');
    }
    if (kemCiphertext.length === 0) {
      throw new Error('Field "kemCiphertext" decoded to zero bytes.');
    }
  } else {
    // PASSWORD mode — decode salt and iterations
    if (typeof obj.salt !== 'string') {
      throw new Error('Field "salt" must be a string (base64).');
    }
    try {
      saltBytes = base64ToBytes(obj.salt);
    } catch {
      throw new Error('Malformed base64 in field "salt".');
    }
    if (saltBytes.length === 0) {
      throw new Error('Field "salt" decoded to zero bytes.');
    }

    iterationsVal = Number(obj.iterations);
    if (!Number.isFinite(iterationsVal) || iterationsVal < 100_000) {
      throw new Error(`Field "iterations" must be >= 100,000, got "${obj.iterations}".`);
    }
  }

  // ── 8. Metadata field types ────────────────────────────────────────────────
  if (typeof obj.originalName !== 'string' || obj.originalName.length === 0) {
    throw new Error('Field "originalName" must be a non-empty string.');
  }

  if (typeof obj.originalExtension !== 'string') {
    throw new Error('Field "originalExtension" must be a string.');
  }

  const originalSize = Number(obj.originalSize);
  if (!Number.isFinite(originalSize) || originalSize < 0) {
    throw new Error(
      `Field "originalSize" must be a non-negative number, got "${obj.originalSize}".`
    );
  }

  // ── 9. Return decoded envelope ─────────────────────────────────────────────
  return {
    mode,
    nonce:             decoded.nonce,
    kemCiphertext,
    wrappedDek:        decoded.wrappedDek,
    ciphertext:        decoded.ciphertext,
    tag:               decoded.tag,
    salt:              saltBytes,
    iterations:        iterationsVal,
    originalName:      obj.originalName,
    originalExtension: obj.originalExtension,
    originalSize,
  };
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Assert that a value is a Uint8Array; throws TypeError otherwise.
 * @param {string} name
 * @param {*}      value
 */
function _assertUint8Array(name, value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(
      `packEnvelope: "${name}" must be a Uint8Array, got ${Object.prototype.toString.call(value)}`
    );
  }
}
