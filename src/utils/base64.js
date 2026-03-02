const { Buffer } = require("node:buffer");

const encode = (str, safeUrl = false) => {
  return Buffer.from(str).toString(safeUrl ? "base64url" : "base64");
};
const decode = (base64str, safeUrl = false) => {
  return Buffer.from(base64str, safeUrl ? "base64url" : "base64").toString(
    "utf8",
  );
};
module.exports = { encode, decode };
