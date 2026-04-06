/**
 * utils.js — Encoding, file I/O, download, and validation helpers
 * PQC File Encryptor · Browser-based ML-KEM-768
 */

// ─── Base64 Encoding / Decoding ───────────────────────────────────────────────

/**
 * Convert a Uint8Array (or ArrayBuffer) to a base64 string.
 * @param {Uint8Array | ArrayBuffer} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

/**
 * Convert a base64 string to a Uint8Array.
 * Throws a descriptive error on malformed input.
 * @param {string} base64
 * @returns {Uint8Array}
 */
export function base64ToBytes(base64) {
  if (typeof base64 !== 'string') {
    throw new Error('base64ToBytes: input must be a string');
  }
  let binary;
  try {
    binary = atob(base64);
  } catch {
    throw new Error('Malformed base64 string — cannot decode');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ─── File Reading ─────────────────────────────────────────────────────────────

/**
 * Read a File object and return its contents as a Uint8Array.
 * @param {File} file
 * @returns {Promise<Uint8Array>}
 */
export function readFileAsBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(new Uint8Array(e.target.result));
    reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`));
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Read a File object and return its contents as a UTF-8 text string.
 * @param {File} file
 * @returns {Promise<string>}
 */
export function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`));
    reader.readAsText(file);
  });
}

// ─── File Download ────────────────────────────────────────────────────────────

/**
 * Trigger a browser download for the given content.
 * @param {string | Uint8Array | ArrayBuffer | Blob} content
 * @param {string} filename
 * @param {string} [mimeType='application/octet-stream']
 */
export function downloadFile(content, filename, mimeType = 'application/octet-stream') {
  const blob =
    content instanceof Blob
      ? content
      : new Blob([content], { type: mimeType });

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  // Revoke the object URL after a short delay to ensure the download starts
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// ─── File Name Helpers ────────────────────────────────────────────────────────

/**
 * Extract the file extension from a filename, including the leading dot.
 * Returns an empty string if there is no extension.
 *
 * Examples:
 *   "secrets.txt"      → ".txt"
 *   "config.env"       → ".env"
 *   ".env"             → ".env"   (dotfile treated as having extension)
 *   "archive.tar.gz"   → ".gz"
 *   "README"           → ""
 *
 * @param {string} filename
 * @returns {string}
 */
export function getFileExtension(filename) {
  if (!filename || typeof filename !== 'string') return '';

  // Special case: dotfiles like ".env" are their own extension
  if (filename.startsWith('.') && filename.indexOf('.', 1) === -1) {
    return filename.toLowerCase();
  }

  const idx = filename.lastIndexOf('.');
  if (idx <= 0) return '';
  return filename.substring(idx).toLowerCase();
}

/**
 * Return the filename without its extension.
 * @param {string} filename
 * @returns {string}
 */
export function getBaseName(filename) {
  const ext = getFileExtension(filename);
  if (!ext) return filename;
  return filename.slice(0, filename.length - ext.length);
}

// ─── File Validation ──────────────────────────────────────────────────────────

/** Maximum allowed file size: 10 MB */
export const MAX_FILE_SIZE = 10 * 1024 * 1024;

/**
 * Return true if the filename has an allowed extension (.txt or .env).
 * @param {string} filename
 * @returns {boolean}
 */
export function isAllowedFileType(filename) {
  if (!filename || typeof filename !== 'string') return false;
  const lower = filename.toLowerCase();
  // Accept .txt files, .env files, and bare ".env" dotfiles
  return (
    lower.endsWith('.txt') ||
    lower.endsWith('.env') ||
    lower === '.env'
  );
}

/**
 * Return true if the file size is within the allowed limit.
 * @param {number} sizeBytes
 * @returns {boolean}
 */
export function isFileSizeAllowed(sizeBytes) {
  return Number.isFinite(sizeBytes) && sizeBytes <= MAX_FILE_SIZE;
}

// ─── Formatting ───────────────────────────────────────────────────────────────

/**
 * Format a byte count into a human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '? B';
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// ─── Password Utilities ───────────────────────────────────────────────────────

/**
 * Generate cryptographically random salt.
 * @param {number} length - Bytes (default: 16)
 * @returns {Uint8Array}
 */
export function generateSalt(length = 16) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Encode a UTF-8 string to Uint8Array.
 * @param {string} str
 * @returns {Uint8Array}
 */
export function stringToBytes(str) {
  return new TextEncoder().encode(str);
}
