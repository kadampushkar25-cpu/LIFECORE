const express = require('express');
const bodyParser = require('body-parser');
const sodium = require('libsodium-wrappers');
const fs = require('fs');
const path = require('path');

const STORAGE_DIR = process.env.STORAGE_DIR || path.join(__dirname, 'received');

// server private key on disk (base64) or via env
const SERVER_PRIV_B64 = process.env.SERVER_PRIV_B64 || (() => {
  try { return fs.readFileSync(path.join(__dirname,'server_priv.b64'),'utf8').trim(); } catch(e){ return null; }
})();

(async() => {
  await sodium.ready;
  if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });

  const app = express();
  app.use(bodyParser.json({ limit: '1mb' }));

  // Store-only endpoint: accepts ciphertext + metadata (from messenger)
  app.post('/receive', (req,res) => {
    const body = req.body || {};
    if (!body.message) return res.status(400).json({error:'missing message'});
    const ts = new Date().toISOString().replace(/[:.]/g,'-');
    const filename = path.join(STORAGE_DIR, `ciphertext-${ts}.json`);
    fs.writeFileSync(filename, JSON.stringify({ received_at: new Date().toISOString(), payload: body }, null, 2));
    console.log('Stored ciphertext payload ->', filename);
    return res.json({ ok:true });
  });

  // PWA endpoint: crypto_box messages (nonce||ct, base64) + sender_pk (base64)
  app.post('/receive_box', (req,res) => {
    if (!SERVER_PRIV_B64) return res.status(500).json({error: "server private key not configured"});
    const { message, sender_pk } = req.body || {};
    if (!message || !sender_pk) return res.status(400).json({error:'missing fields'});
    try {
      const priv = sodium.from_base64(SERVER_PRIV_B64, sodium.base64_variants.ORIGINAL);
      const senderPk = sodium.from_base64(sender_pk, sodium.base64_variants.ORIGINAL);
      const payload = sodium.from_base64(message, sodium.base64_variants.ORIGINAL);
      const nonce = payload.slice(0, sodium.crypto_box_NONCEBYTES);
      const ct = payload.slice(sodium.crypto_box_NONCEBYTES);
      const plain = sodium.crypto_box_open_easy(ct, nonce, senderPk, priv);
      const plaintext = sodium.to_string(plain);
      const ts = new Date().toISOString().replace(/[:.]/g,'-');
      const filename = path.join(STORAGE_DIR, `pwa-${ts}.txt`);
      fs.writeFileSync(filename, plaintext);
      console.log("Decrypted PWA message ->", filename);
      return res.json({ ok:true, plaintext });
    } catch (e) {
      console.error("decrypt error:", e);
      return res.status(500).json({error:'decrypt_failed'});
    }
  });

  const port = process.env.PORT || 3000;
  app.listen(port, ()=>console.log('LIFECORE server running on', port));
})();
