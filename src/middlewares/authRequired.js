const authConfig = require("@/config/auth");
const db = require("@/config/database");
const authService = require("@/services/auth.service");

async function authRequired(req, res, next) {
  const accessToken = req.headers?.authorization?.slice(6).trim();

  if (!accessToken) return res.error(401, null, "Unauthorized");

  const payload = await authService.verifyAccessToken(accessToken);

  //check blacklist
  const [[{ count }]] = await db.query(
    `select count(*) as count from revoked_tokens where token=?`,
    [accessToken],
  );

  if (count > 0 || payload.exp < Date.now()) {
    return res.error(401, null, "Unauthorized");
  }
  const [users] = await db.query(
    `select id,email,created_at from users where id=?`,
    [payload.sub],
  );
  const user = users[0];
  if (!user) {
    return res.error(401, null, "Unauthorized");
  }
  req.currentUser = user;
  req.accessToken = accessToken;
  req.tokenPayload = payload;
  next();
}
module.exports = authRequired;
