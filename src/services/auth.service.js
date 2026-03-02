const authConfig = require("@/config/auth");
const jwt = require("jsonwebtoken");
const base64 = require("../utils/base64");
const crypto = require("crypto");
const JsonWebTokenError = require("@/classes/errors/jsonWebTokenError");
const randomKey = require("@/utils/randomKey");
const authModel = require("@/models/auth.model");
const db = require("@/config/database");

class AuthService {
  async signAccessToken(id) {
    const ttl = authConfig.accessTokenTTL;
    console.log(ttl);
    const accessToken = await jwt.sign(
      {
        sub: id,
        exp: parseInt(Date.now() / 1000 + ttl),
      },
      process.env.AUTH_JWT_SECRET,
    );
    return accessToken;
  }
  async verifyAccessToken(accessToken) {
    const payload = jwt.verify(accessToken, authConfig.jwtSecret);
    return payload;
  }
  async createRefreshToken(user, userAgent) {
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + authConfig.refreshTokenTTL);
    let refreshToken,
      isExists = false;
    do {
      refreshToken = randomKey();
      const [[{ count }]] = await db.query(
        "select count(*) as count from refresh_tokens where token=?",
        [refreshToken],
      );
      isExists = count > 0;
    } while (isExists);
    await authModel.insertRefreshToken(
      user.id,
      refreshToken,
      expires_at,
      userAgent,
    );
    return refreshToken;
  }
  generateVerificationLink(user) {
    const payload = {
      sub: user.id,
      exp: Date.now() / 1000 + authConfig.ve,
    };
    const token = jwt.sign(payload, authConfig.verificationJwtSecret);
    const verificationLink = `http://localhost:5173?token=${token}`;
    return verificationLink;
  }
  async verifyEmail(token) {
    const payload = jwt.verify(token, authConfig.verificationJwtSecret);
    console.log(payload);
  }
}
module.exports = new AuthService();
