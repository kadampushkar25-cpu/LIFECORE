// encrypt-and-send.js (client-side). Uses server public-key encryption (crypto_box)
(async () => {
  await sodium.ready;
  const serverPubKeyB64 = '<PUT_SERVER_PUBKEY_B64_HERE>'; // get from server
  const endpoint = 'https://httpbin.org/post'; // replace with your server
  const sendBtn = document.getElementById('send');
  const status = document.getElementById('status');
  sendBtn.onclick = async () => {
    try {
      const msg = document.getElementById('msg').value;
      const serverPub = sodium.from_base64(serverPubKeyB64, sodium.base64_variants.ORIGINAL);
      // Generate ephemeral keypair (or reuse a persistent client key)
      const kp = sodium.crypto_box_keypair();
      const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
      const cipher = sodium.crypto_box_easy(sodium.from_string(msg), nonce, serverPub, kp.privateKey);
      const payload = sodium.to_base64(sodium.concat(nonce, cipher), sodium.base64_variants.ORIGINAL);
      const body = JSON.stringify({ message: payload, sender_pk: sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL) });
      const r = await fetch(endpoint, { method: 'POST', headers: {'Content-Type':'application/json'}, body });
      status.innerText = 'Sent. Server response status: ' + r.status;
    } catch (e) {
      status.innerText = 'Error: ' + e;
    }
  };
})();
