const db = require("@/config/database");

const logout = async (accessToken, tokenPayload) => {
  const query = `insert into revoked_tokens (token,expires_at) values (?,?)`;
  await db.query(query, [accessToken, new Date(tokenPayload.exp)]);
};
module.exports = { logout };
