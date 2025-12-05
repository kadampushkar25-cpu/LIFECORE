Contributing to LIFECORE

Thank you for your interest in improving LIFECORE — a safety-critical communication kernel.  
Our priority is security, correctness, and clarity of implementation.

---

🧠 Principles
1. Security first — no feature outweighs correctness.  
2. Minimalism — small, auditable, dependency-light code.  
3. Deterministic behaviour — avoid undefined or platform-specific quirks.  
4. Privacy by design — no plaintext persists anywhere.

---

🛠 Code Contributions

1. Fork → Branch → PR
git checkout -b feature/<name>

2. Requirements

C++17 or higher

libsodium 1.0.18+

libcurl (optional, for transport)

Code must pass make test

3. Style

Use clear naming (masterKey, logKey, etc.)

Keep encryption logic isolated in Encryption.h

Avoid macros unless essential

Document public methods

4. Tests

All crypto-related code must include:

Encryption/decryption roundtrip tests

Failure-case tests (wrong key / corrupted ciphertext)

5. Pull Requests

Include in the PR:

Clear description of change

Why it’s needed

Any security implications

Test results logs

---

🐛 Reporting Bugs

Open an issue with:

Steps to reproduce

Logs and exact output

Platform (WSL/Ubuntu/Windows/macOS)

Expected vs actual behaviour

🛡 Security Issues

Do not open public issues.
See SECURITY.md for responsible disclosure process.

❤️ Thank You

Every contribution helps strengthen a tool designed to protect people when it matters most.
