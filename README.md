<p align="center">
  <img src="https://img.shields.io/badge/status-active-brightgreen" />
  <img src="https://img.shields.io/badge/security-high-critical" />
  <img src="https://img.shields.io/badge/license-MIT-blue" />
  <img src="https://img.shields.io/badge/built_with-C++17-lightgrey" />
  <img src="https://img.shields.io/badge/crypto-AEAD%20XChaCha20--Poly1305-orange" />
  <img src="https://img.shields.io/badge/KDF-Argon2id-red" />
  <img src="https://img.shields.io/badge/platform-LIFECORE-black" />
</p>

---

🔐 LIFECORE  
A future-ready emergency communication kernel designed for the moments where ordinary systems fail.

LIFECORE provides a reliable, secure, and unstoppable channel for urgent human signals.  
It exists because today’s communication tools are slow, fragile, and not built for life-critical urgency.  
LIFECORE redesigns emergency messaging from the ground up — **private, instant, unforgeable, and resilient.

---

🌍 Why LIFECORE Exists
Emergencies expose weaknesses in every communication system:
- Messages fail under load  
- Signals get delayed or lost  
- Data leaks risk lives  
- Internet connectivity may be partial or unstable  
- Existing apps aren’t designed for panic, danger, or impact

LIFECORE aims to become the always-available safety layer** — a minimal, secure kernel built ahead of its time that makes sure an SOS is never ignored, lost, or compromised.

---

🚀 Key Capabilities
- End-to-end encryption (XChaCha20-Poly1305 AEAD)  
  Every message is encrypted in memory, on disk, and during transport.

- Strong key derivation (Argon2id)  
  Passphrase-based master key protected by a persistent per-user salt.

- Encrypted-at-rest logs  
  Each log entry is wrapped with a dedicated `logKey` for metadata privacy.

- Secure transport 
  Only ciphertext is sent over HTTPS — servers never see plaintext unless authorized.

- PWA SOS Client 
  Browser-based emergency agent that encrypts client-side using Curve25519.

- Key rotation support  
  Rotate passphrases without losing message access.

- Recovery tools 
  Decrypt logs, sanitize plaintext histories, and migrate older encryption formats.

- Lightweight, auditable C++ kernel 
  Minimal external dependencies; designed for inspection and trust.

---

🏗 Project Structure

LIFECORE/
├── Encryption.h # Argon2id + AEAD crypto engine
├── MessageQueue.h / .cpp # Encrypted message queue + log encryption
├── main.cpp # LIFECORE kernel entrypoint
│
├── rotate_keys.cpp # Rewrap logKey when passphrase changes
├── reencrypt_log.cpp # Sanitize plaintext logs → encrypted logs
├── decrypt_log_line.cpp # Decrypt a single log entry for debugging
├── try_all_salts_and_decrypt.cpp # Salt/key recovery helper (advanced)
│
├── modules/
│ └── emergency_messenger/
│ ├── keys/ # salt + wrapped_logkey.bin
│ └── logs/ # encrypted log entries
│
├── pwa/
│ ├── index.html # SOS web client UI
│ ├── encrypt-and-send.js # client-side end-to-end encryption
│ ├── sw.js # service worker (offline-ready)
│ └── manifest.json # PWA manifest
│
├── server/
│ ├── server.js # ciphertext receiver + decrypting endpoint
│ ├── package.json
│ └── Dockerfile
│
├── Makefile # build system for kernel + tests
└── .github/workflows/ci.yml # CI: build + crypto tests

---

Open in your browser:
👉 http://localhost:8080

---

🔐 Security Model Overview
Encryption:

Messages encrypted: XChaCha20-Poly1305 AEAD

Key derivation: Argon2id with user-specific salt

Logs encrypted using a dedicated logKey

All sensitive keys zeroed from memory

Data at rest:

Never stores plaintext

Each log entry is:
wrapped_record = AEAD_encrypt(record_plain, logKey)

Data in motion:

Transport layer only sees ciphertext

PWA uses server public key for crypto_box encryption

Messenger posts ciphertext + metadata (priority)

Key persistence:

user_salt.bin — needed to derive masterKey

wrapped_logkey.bin — wrapped with masterKey, required for log decryption

Losing these makes old records unrecoverable (by design)

---

🛠 Development Roadmap

Real-time encrypted transport (WebSocket/QUIC)

Mobile-native wrapper for PWA client

Distributed key double-wrapping for multi-node trust

Emergency geolocation encryption

Rate-limited blast channels for life-critical alerts

---

🤝 Contributing

Pull requests welcome — LIFECORE is designed to be auditable, extendable, and community-driven.
Open an issue for new suggestions or improvement ideas.

---

📄 License

Licensed under the MIT License.
See LICENSE and THIRD_PARTY_LICENSES.md for details.
