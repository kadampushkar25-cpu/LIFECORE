// server.js
const express = require('express');
const bodyParser = require('body-parser');
const sodium = require('libsodium-wrappers');
const fs = require('fs');

const SERVER_PRIV = process.env.SERVER_PRIV_B64 || fs.readFileSync('server_priv.b64','utf8').trim();

(async () => {
  await sodium.ready;
  const app = express();
  app.use(bodyParser.json({ limit: '1mb' }));

  // endpoint for messenger (just accept ciphertext)
  app.post('/receive', (req, res) => {
    console.log("/receive body:", req.body);
    // store or forward as needed
    res.json({ ok: true });
  });

  // endpoint for PWA crypto_box messages
  app.post('/receive_box', (req, res) => {
    try {
      const { message, sender_pk } = req.body;
      if (!message || !sender_pk) return res.status(400).json({ error: 'bad request' });

      const priv = sodium.from_base64(SERVER_PRIV, sodium.base64_variants.ORIGINAL);
      const senderPk = sodium.from_base64(sender_pk, sodium.base64_variants.ORIGINAL);
      const payload = sodium.from_base64(message, sodium.base64_variants.ORIGINAL);
      const nonce = payload.slice(0, sodium.crypto_box_NONCEBYTES);
      const ct = payload.slice(sodium.crypto_box_NONCEBYTES);

      // decrypt: crypto_box_open_easy requires ciphertext+nonce+sender_pk+server_priv
      const msg = sodium.crypto_box_open_easy(ct, nonce, senderPk, priv);
      const plaintext = sodium.to_string(msg);
      console.log("Decrypted PWA message from sender:", plaintext);
      res.json({ ok: true, plaintext });
    } catch (e) {
      console.error("decrypt error", e);
      res.status(500).json({ error: 'decrypt failed' });
    }
  });

  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log("Server listening on", port));
})();
