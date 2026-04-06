import {
  bytesToBase64,
  base64ToBytes,
  readFileAsBytes,
  readFileAsText,
  downloadFile,
  getFileExtension,
  isAllowedFileType,
  isFileSizeAllowed,
  formatBytes,
  MAX_FILE_SIZE,
  generateSalt,
  stringToBytes,
} from "./lib/utils.js";

import {
  generateKeyPair,
  serializePublicKey,
  serializePrivateKey,
  parsePublicKey,
  parsePrivateKey,
  encapsulate,
  decapsulate,
  deriveKEK,
  deriveKEKFromPassword,
  wrapDEK,
  unwrapDEK,
  encryptAESGCM,
  decryptAESGCM,
  generateDEK,
} from "./lib/crypto.js";

import {
  packEnvelope,
  unpackEnvelope,
  buildAAD,
  ENVELOPE_MODE_KEYPAIR,
  ENVELOPE_MODE_PASSWORD,
} from "./lib/envelope.js";

import {
  generateStrongPassword,
  estimatePasswordStrength,
} from "./lib/password.js";

const state = {
  publicKey: null,
  privateKey: null,
  keyPair: null,
  encryptionMode: "keypair",
  decryptMode: "keypair",
};

function showStatus(elementId, message, type) {
  const el = document.getElementById(elementId);
  el.className = "status-box " + type;
  el.textContent = message;
}

function clearStatus(elementId) {
  const el = document.getElementById(elementId);
  el.className = "status-box";
  el.textContent = "";
}

function updateKeyBadges() {
  const pubBadge = document.getElementById("badge-public");
  const privBadge = document.getElementById("badge-private");
  const downloadPubBtn = document.getElementById("btn-download-public");
  const downloadPrivBtn = document.getElementById("btn-download-private");
  const resetBtn = document.getElementById("btn-reset");
  const encryptBtn = document.getElementById("btn-encrypt");
  const decryptBtn = document.getElementById("btn-decrypt");

  if (state.publicKey) {
    pubBadge.className = "badge badge-public";
    pubBadge.textContent = "Public Key Loaded";
    downloadPubBtn.disabled = false;
  } else {
    pubBadge.className = "badge badge-empty";
    pubBadge.textContent = "No Public Key";
    downloadPubBtn.disabled = true;
  }

  if (state.privateKey) {
    privBadge.className = "badge badge-private";
    privBadge.textContent = "Private Key Loaded";
    downloadPrivBtn.disabled = false;
    resetBtn.disabled = false;
  } else {
    privBadge.className = "badge badge-empty";
    privBadge.textContent = "No Private Key";
    downloadPrivBtn.disabled = true;
    resetBtn.disabled = true;
  }

  if (state.encryptionMode === "keypair") {
    encryptBtn.disabled = !state.publicKey;
    decryptBtn.disabled = !state.privateKey;
  } else {
    encryptBtn.disabled = false;
    decryptBtn.disabled = false;
  }
}

function checkSecureContext() {
  const isSecure =
    window.isSecureContext ||
    window.location.protocol === "https:" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";
  if (!isSecure) {
    const errorEl = document.getElementById("runtime-error");
    errorEl.textContent =
      "Error: This application requires a secure context (HTTPS or localhost). Please serve via HTTPS or localhost.";
    errorEl.classList.remove("hidden");
    throw new Error("Insecure context");
  }
}

function checkWebCrypto() {
  if (!window.crypto || !window.crypto.subtle) {
    const errorEl = document.getElementById("runtime-error");
    errorEl.textContent =
      "Error: WebCrypto API not available. Please use a modern browser (Chrome, Edge, Firefox).";
    errorEl.classList.remove("hidden");
    throw new Error("WebCrypto not available");
  }
}

function setEncryptMode(mode) {
  state.encryptionMode = mode;
  const pwSection = document.getElementById("encrypt-password-section");
  const keySection = document.getElementById("key-management");
  if (mode === "password") {
    pwSection.classList.remove("hidden");
    keySection.classList.add("hidden");
  } else {
    pwSection.classList.add("hidden");
    keySection.classList.remove("hidden");
  }
  updateKeyBadges();
}

function setDecryptMode(mode) {
  state.decryptMode = mode;
  const pwSection = document.getElementById("decrypt-password-section");
  const keySection = document.getElementById("key-management");
  if (mode === "password") {
    pwSection.classList.remove("hidden");
    keySection.classList.add("hidden");
  } else {
    pwSection.classList.add("hidden");
    keySection.classList.remove("hidden");
  }
  updateKeyBadges();
}

function updateStrengthMeter(inputEl, meterEl, labelEl) {
  const result = estimatePasswordStrength(inputEl.value);
  labelEl.textContent =
    result.label + (result.bits > 0 ? ` (${result.bits} bits)` : "");
  labelEl.className = "strength-label strength-" + result.score;
  const bar = meterEl.querySelector(".strength-bar");
  bar.style.width = (result.score / 4) * 100 + "%";
  bar.className = "strength-bar strength-bar-" + result.score;
}

function init() {
  checkSecureContext();
  checkWebCrypto();

  const themeBtn = document.getElementById("btn-dark-mode");
  const savedTheme = localStorage.getItem("theme") || "light";
  if (savedTheme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
    themeBtn.textContent = "☀️ Light Mode";
  }
  themeBtn.addEventListener("click", () => {
    const isDark =
      document.documentElement.getAttribute("data-theme") === "dark";
    if (isDark) {
      document.documentElement.removeAttribute("data-theme");
      localStorage.setItem("theme", "light");
      themeBtn.textContent = "🌙 Dark Mode";
    } else {
      document.documentElement.setAttribute("data-theme", "dark");
      localStorage.setItem("theme", "dark");
      themeBtn.textContent = "☀️ Light Mode";
    }
  });

  document
    .getElementById("btn-generate")
    .addEventListener("click", handleGenerateKeypair);
  document
    .getElementById("btn-download-public")
    .addEventListener("click", handleDownloadPublicKey);
  document
    .getElementById("btn-download-private")
    .addEventListener("click", handleDownloadPrivateKey);
  document.getElementById("btn-reset").addEventListener("click", handleReset);
  document
    .getElementById("input-public-key")
    .addEventListener("change", handleImportPublicKey);
  document
    .getElementById("input-private-key")
    .addEventListener("change", handleImportPrivateKey);
  document
    .getElementById("btn-encrypt")
    .addEventListener("click", handleEncrypt);
  document
    .getElementById("btn-decrypt")
    .addEventListener("click", handleDecrypt);

  // Mode toggles
  document.querySelectorAll('input[name="encrypt-mode"]').forEach((radio) => {
    radio.addEventListener("change", (e) => setEncryptMode(e.target.value));
  });
  document.querySelectorAll('input[name="decrypt-mode"]').forEach((radio) => {
    radio.addEventListener("change", (e) => setDecryptMode(e.target.value));
  });

  // Generate password button
  document
    .getElementById("btn-generate-password")
    .addEventListener("click", () => {
      const pwInput = document.getElementById("encrypt-password");
      pwInput.value = generateStrongPassword(24);
      pwInput.type = "text";
      document.getElementById("btn-toggle-encrypt-visibility").textContent =
        "🙈";
      updateStrengthMeter(
        pwInput,
        document.getElementById("password-strength"),
        document.getElementById("strength-label"),
      );
    });

  // Password visibility toggles
  document
    .getElementById("btn-toggle-encrypt-visibility")
    .addEventListener("click", () => {
      const pwInput = document.getElementById("encrypt-password");
      const btn = document.getElementById("btn-toggle-encrypt-visibility");
      if (pwInput.type === "password") {
        pwInput.type = "text";
        btn.textContent = "🫣";
      } else {
        pwInput.type = "password";
        btn.textContent = "👁";
      }
    });

  document
    .getElementById("btn-toggle-decrypt-visibility")
    .addEventListener("click", () => {
      const pwInput = document.getElementById("decrypt-password");
      const btn = document.getElementById("btn-toggle-decrypt-visibility");
      if (pwInput.type === "password") {
        pwInput.type = "text";
        btn.textContent = "🙈";
      } else {
        pwInput.type = "password";
        btn.textContent = "👁";
      }
    });

  // Password strength meter (encrypt only — decrypt just needs exact match)
  document.getElementById("encrypt-password").addEventListener("input", () => {
    updateStrengthMeter(
      document.getElementById("encrypt-password"),
      document.getElementById("password-strength"),
      document.getElementById("strength-label"),
    );
  });

  updateKeyBadges();
}

async function handleGenerateKeypair() {
  try {
    const keyPair = generateKeyPair();
    state.keyPair = keyPair;
    state.publicKey = keyPair.publicKey;
    state.privateKey = keyPair.privateKey;
    updateKeyBadges();
    showStatus("encrypt-status", "Keypair generated successfully!", "success");
  } catch (err) {
    showStatus(
      "encrypt-status",
      "Key generation failed: " + err.message,
      "error",
    );
  }
}

function handleDownloadPublicKey() {
  if (!state.publicKey) return;
  try {
    const json = serializePublicKey(state.publicKey);
    downloadFile(json, "public-key.mlkem.json", "application/json");
    showStatus("encrypt-status", "Public key downloaded", "success");
  } catch (err) {
    showStatus("encrypt-status", "Download failed: " + err.message, "error");
  }
}

function handleDownloadPrivateKey() {
  if (!state.privateKey) return;
  const confirmed = confirm(
    "⚠️ WARNING: Store this file securely! Losing your private key means permanent data loss.",
  );
  if (!confirmed) return;
  try {
    const json = serializePrivateKey(state.privateKey);
    downloadFile(json, "private-key.mlkem.json", "application/json");
    showStatus(
      "encrypt-status",
      "Private key downloaded - keep it safe!",
      "success",
    );
  } catch (err) {
    showStatus("encrypt-status", "Download failed: " + err.message, "error");
  }
}

async function handleImportPublicKey(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await readFileAsText(file);
    const keyData = parsePublicKey(text);
    state.publicKey = keyData;
    updateKeyBadges();
    showStatus(
      "encrypt-status",
      "Public key imported successfully!",
      "success",
    );
  } catch (err) {
    showStatus("encrypt-status", "Import failed: " + err.message, "error");
  }
  e.target.value = "";
}

async function handleImportPrivateKey(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await readFileAsText(file);
    const keyData = parsePrivateKey(text);
    state.privateKey = keyData;
    updateKeyBadges();
    showStatus(
      "decrypt-status",
      "Private key imported successfully!",
      "success",
    );
  } catch (err) {
    showStatus("decrypt-status", "Import failed: " + err.message, "error");
  }
  e.target.value = "";
}

function handleReset() {
  state.publicKey = null;
  state.privateKey = null;
  state.keyPair = null;
  updateKeyBadges();
  clearStatus("encrypt-status");
  clearStatus("decrypt-status");
  document.getElementById("input-encrypt-file").value = "";
  document.getElementById("input-decrypt-file").value = "";
  showStatus("encrypt-status", "All keys cleared from memory", "info");
}

async function handleEncrypt() {
  const fileInput = document.getElementById("input-encrypt-file");
  const file = fileInput.files[0];
  if (!file) {
    showStatus("encrypt-status", "Please select a file to encrypt", "error");
    return;
  }

  try {
    const ext = getFileExtension(file.name);
    if (!isAllowedFileType(file.name)) {
      throw new Error(
        "Unsupported file type. Only .txt and .env files are allowed.",
      );
    }

    if (!isFileSizeAllowed(file.size)) {
      throw new Error(
        "File too large. Maximum size is " + formatBytes(MAX_FILE_SIZE),
      );
    }

    const plaintext = await readFileAsBytes(file);
    const dek = await generateDEK();
    const aad = buildAAD(file.name, ext, file.size);
    const { ciphertext, tag, nonce } = await encryptAESGCM(plaintext, dek, aad);

    let envelope;

    if (state.encryptionMode === "password") {
      const password = document.getElementById("encrypt-password").value;
      if (!password || password.length < 8) {
        throw new Error(
          "Password must be at least 8 characters. Use the Generate button for a strong password.",
        );
      }

      const salt = generateSalt(16);
      const passwordBytes = stringToBytes(password);
      const kek = await deriveKEKFromPassword(passwordBytes, salt);
      const wrappedDek = await wrapDEK(dek, kek);

      envelope = packEnvelope({
        wrappedDek,
        ciphertext,
        tag,
        nonce,
        originalName: file.name,
        originalExtension: ext,
        originalSize: file.size,
        mode: ENVELOPE_MODE_PASSWORD,
        salt,
        iterations: 600_000,
      });
    } else {
      if (!state.publicKey) {
        throw new Error("Public key required for keypair mode.");
      }

      const { kemCiphertext, sharedSecret } = encapsulate(state.publicKey);
      const kek = await deriveKEK(sharedSecret);
      const wrappedDek = await wrapDEK(dek, kek);

      envelope = packEnvelope({
        kemCiphertext,
        wrappedDek,
        ciphertext,
        tag,
        nonce,
        originalName: file.name,
        originalExtension: ext,
        originalSize: file.size,
        mode: ENVELOPE_MODE_KEYPAIR,
      });
    }

    const outputName = file.name + ".pqenc.json";
    downloadFile(envelope, outputName, "application/json");
    showStatus(
      "encrypt-status",
      "File encrypted successfully! Downloaded: " + outputName,
      "success",
    );
  } catch (err) {
    showStatus("encrypt-status", "Encryption failed: " + err.message, "error");
  }

  fileInput.value = "";
}

async function handleDecrypt() {
  const fileInput = document.getElementById("input-decrypt-file");
  const file = fileInput.files[0];
  if (!file) {
    showStatus("decrypt-status", "Please select a file to decrypt", "error");
    return;
  }

  try {
    const text = await readFileAsText(file);
    const envelope = unpackEnvelope(text);

    const {
      mode,
      kemCiphertext,
      wrappedDek,
      ciphertext,
      tag,
      nonce,
      salt,
      iterations,
      originalName,
      originalExtension,
      originalSize,
    } = envelope;

    let dek;

    if (mode === ENVELOPE_MODE_PASSWORD) {
      const password = document.getElementById("decrypt-password").value;
      if (!password) {
        throw new Error("Password required to decrypt this file.");
      }

      const passwordBytes = stringToBytes(password);
      const kek = await deriveKEKFromPassword(passwordBytes, salt, iterations);
      dek = await unwrapDEK(wrappedDek, kek);
    } else {
      if (!state.privateKey) {
        throw new Error("Private key required for keypair mode.");
      }

      if (state.privateKey.length !== 2400) {
        throw new Error(
          "Invalid private key: expected 2400 bytes (ML-KEM-768 secret key), got " +
            state.privateKey.length +
            " bytes.",
        );
      }

      const sharedSecret = decapsulate(kemCiphertext, state.privateKey);
      const kek = await deriveKEK(sharedSecret);
      dek = await unwrapDEK(wrappedDek, kek);
    }

    const aad = buildAAD(originalName, originalExtension, originalSize);
    const plaintext = await decryptAESGCM(ciphertext, tag, dek, nonce, aad);

    downloadFile(plaintext, originalName);
    showStatus(
      "decrypt-status",
      "File decrypted successfully! Restored: " +
        originalName +
        " (" +
        formatBytes(plaintext.length) +
        ")",
      "success",
    );
  } catch (err) {
    showStatus("decrypt-status", "Decryption failed: " + err.message, "error");
  }

  fileInput.value = "";
}

document.addEventListener("DOMContentLoaded", init);
