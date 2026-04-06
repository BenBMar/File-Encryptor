/**
 * password.js
 * Password generation and strength estimation for the PQC File Encryptor.
 */

/**
 * Generate a cryptographically strong random password.
 * @param {number} length - Default: 24 (~150 bits of entropy)
 * @returns {string}
 */
export function generateStrongPassword(length = 24) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset[bytes[i] % charset.length];
  }
  return password;
}

/**
 * Estimate password strength.
 * @param {string} password
 * @returns {{ score: number, label: string, bits: number }}
 */
export function estimatePasswordStrength(password) {
  if (!password || password.length === 0) {
    return { score: 0, label: 'Very Weak', bits: 0 };
  }

  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  if (charsetSize === 0) return { score: 0, label: 'Very Weak', bits: 0 };

  const bits = Math.floor(password.length * Math.log2(charsetSize));

  let score, label;
  if (bits < 36)       { score = 0; label = 'Very Weak'; }
  else if (bits < 60)  { score = 1; label = 'Weak'; }
  else if (bits < 80)  { score = 2; label = 'Fair'; }
  else if (bits < 120) { score = 3; label = 'Strong'; }
  else                 { score = 4; label = 'Very Strong'; }

  return { score, label, bits };
}
