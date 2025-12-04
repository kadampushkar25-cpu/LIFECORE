// gen_server_keypair.js
const sodium = require('libsodium-wrappers');
(async () => {
  await sodium.ready;
  const kp = sodium.crypto_box_keypair();
  console.log("SERVER_PUBLIC_KEY_B64=" + sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL));
  console.log("SERVER_PRIVATE_KEY_B64=" + sodium.to_base64(kp.privateKey, sodium.base64_variants.ORIGINAL));
})();
