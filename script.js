let publicKey, privateKey, aesKey;

window.onload = async () => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );
  publicKey = keyPair.publicKey;
  privateKey = keyPair.privateKey;
};

// ✅ AES-GCM + RSA Encryption
async function encryptMessage() {
  const msg = document.getElementById("message").value;
  const encoder = new TextEncoder();
  const encoded = encoder.encode(msg);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  aesKey = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoded
  );

  const exportedKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const encryptedAesKey = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    exportedKey
  );

  document.getElementById("encryptedMessage").value =
    btoa(String.fromCharCode(...iv, ...new Uint8Array(encrypted)));

  document.getElementById("encryptedKey").value =
    btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey)));
}

// ✅ AES-GCM + RSA Decryption
async function decryptMessage() {
  const encryptedMsgBase64 = document.getElementById("encryptedMessage").value;
  const encryptedKeyBase64 = document.getElementById("encryptedKey").value;

  const encryptedKey = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));
  const rawKey = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedKey
  );

  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  const encryptedMsg = Uint8Array.from(atob(encryptedMsgBase64), c => c.charCodeAt(0));
  const iv = encryptedMsg.slice(0, 12);
  const data = encryptedMsg.slice(12);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data
  );

  const decoded = new TextDecoder().decode(decrypted);
  document.getElementById("decryptedMessage").value = decoded;
}

// Caesar Encrypt
function encryptCaesar() {
  const text = document.getElementById('caesarInput').value;
  const shift = parseInt(document.getElementById('shift').value);
  const encrypted = text.split('').map(char => {
    if (/[a-z]/.test(char)) {
      return String.fromCharCode((char.charCodeAt(0) - 97 + shift) % 26 + 97);
    } else if (/[A-Z]/.test(char)) {
      return String.fromCharCode((char.charCodeAt(0) - 65 + shift) % 26 + 65);
    }
    return char;
  }).join('');
  document.getElementById("caesarResult").value = encrypted;
}

// Caesar Decrypt (✅ FIXED TO USE ENCRYPTED RESULT)
function decryptCaesar() {
  const text = document.getElementById('caesarResult').value; // 🔥 Use encrypted result!
  const shift = parseInt(document.getElementById('shift').value);
  const decrypted = text.split('').map(char => {
    if (/[a-z]/.test(char)) {
      return String.fromCharCode((char.charCodeAt(0) - 97 - shift + 26) % 26 + 97);
    } else if (/[A-Z]/.test(char)) {
      return String.fromCharCode((char.charCodeAt(0) - 65 - shift + 26) % 26 + 65);
    }
    return char;
  }).join('');
  document.getElementById("caesarResult").value = decrypted;
}
// ✅ Toggle Theme
function toggleTheme() {
  document.body.classList.toggle('light');
  localStorage.setItem('theme', document.body.classList.contains('light') ? 'light' : 'dark');
}

// ✅ On Load, Apply Saved Theme
window.onload = () => {
  if (localStorage.getItem('theme') === 'light') {
    document.body.classList.add('light');
  }
}
