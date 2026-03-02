const crypto = require("node:crypto");

function randomKey(size = 32, encode = "hex") {
  const keyBuffer = crypto.randomBytes(size);
  const keyHex = keyBuffer.toString(encode);

  return keyHex;
}
module.exports = randomKey;
