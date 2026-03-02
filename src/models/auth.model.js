const db = require("@/config/database");

const getInfoUserLogin = async (email) => {
  const [users] = await db.query(`select * from users where email =?`, [email]);
  const user = users[0];
  return user;
};
const registerUser = async (email, password) => {
  const [{ insertId }] = await db.query(
    `insert into users (email,password) values (?,?)`,
    [email, password],
  );
  return insertId;
};
const logout = async (accessToken, tokenPayload) => {
  const query = `insert into revoked_tokens (token,expires_at) values (?,?)`;
  await db.query(query, [accessToken, new Date(tokenPayload.exp)]);
};
const insertRefreshToken = async (id, refreshToken, expires_at, userAgent) => {
  await db.query(
    "insert into refresh_tokens (user_id,token,expires_at,user_agent) values (?,?,?,?)",
    [id, refreshToken, expires_at, userAgent],
  );
};

const selectRefreshToken = async (refresh_token) => {
  const [rows] = await db.query(
    "select id,user_id from refresh_tokens where token = ? and expires_at >= now() and is_revoked = 0 limit 1",
    [refresh_token],
  );
  return rows[0];
};
const updateRevokedRefreshToken = async (refreshTokenDB) => {
  await db.query("update refresh_tokens set  is_revoked=1 where id=?", [
    refreshTokenDB.id,
  ]);
};
module.exports = {
  getInfoUserLogin,
  registerUser,
  logout,
  insertRefreshToken,
  selectRefreshToken,
  updateRevokedRefreshToken,
};
