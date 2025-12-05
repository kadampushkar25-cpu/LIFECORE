🔐 SECURITY.md

SECURITY POLICY

LIFECORE is a safety-critical project.  
We follow strict security procedures for vulnerability handling.

---

🚨 Reporting a Vulnerability

Do NOT open a GitHub issue.  
Instead, email:

📧 lifecore-security@protonmail.com  

Include:
- Description of the issue  
- Steps to reproduce  
- Impact assessment  
- Suggested fix (optional)

We will:
1. Acknowledge within 48 hours  
2. Investigate within 7 days  
3. Patch and privately coordinate a fix  
4. Disclose responsibly after resolution  

---

🔒 Scope
- Encryption logic (AEAD, Argon2id)  
- Key wrapping / unwrapping  
- Log sanitation tools  
- PWA encryption logic  
- Server crypto_box decryption path  
- Memory handling (zeroing, key lifetime)  

---

🛑 Out of Scope
- Issues caused by user misconfiguration  
- Network outages / transport errors  
- Fake emergency usage on non-production servers  

---

🔄 Patch Lifecycle
- Patch developed privately  
- Reviewed by maintainers  
- Regression tests updated  
- Public release with CVE (if necessary)

---

🧱 Commitment
LIFECORE is built for life-critical scenarios.  
Security is not a feature — it is the foundation.
