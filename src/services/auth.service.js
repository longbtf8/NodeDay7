const authConfig = require("@/config/auth");
const jwt = require("jsonwebtoken");
const base64 = require("../utils/base64");
const crypto = require("crypto");
const JsonWebTokenError = require("@/classes/errors/jsonWebTokenError");
const randomKey = require("@/utils/randomKey");
const authModel = require("@/models/auth.model");
const db = require("@/config/database");

const jwt2 = {
  sign(payload, secret) {
    //header
    const header = JSON.stringify({
      typ: "JWT",
      alg: "HS256",
    });
    const encodedHeader = base64.encode(header, true);
    const encodedPayload = base64.encode(JSON.stringify(payload), true);
    // signature
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(`${encodedHeader}.${encodedPayload}`);
    const signature = hmac.digest("base64url");

    //jwt token
    const token = `${encodedHeader}.${encodedPayload}.${signature}`;
    return token;
  },
  verify(token, secret) {
    //encodedHeader , encodedPayload,signature
    const tokens = token?.split(".");
    if (!tokens) throw new JsonWebTokenError("No token");
    const encodedHeader = tokens[0];
    const encodedPayload = tokens[1];
    const oldSignature = tokens[2];

    // signature
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(`${encodedHeader}.${encodedPayload}`);

    // new signature
    const newSignature = hmac.digest("base64url");

    const isValid = newSignature === oldSignature;
    console.log(isValid);
    if (isValid) {
      const result = JSON.parse(base64.decode(encodedPayload, true));
      return result;
    }

    //throw JsonWebTokenError
    throw new JsonWebTokenError("Invalid Token");
  },
};

class AuthService {
  async signAccessToken(id) {
    const ttl = authConfig.accessTokenTTL;
    console.log(ttl);
    const accessToken = await jwt2.sign(
      {
        sub: id,
        exp: parseInt(Date.now() + ttl * 1000),
      },
      process.env.AUTH_JWT_SECRET,
    );
    return accessToken;
  }
  async verifyAccessToken(accessToken) {
    const payload = jwt2.verify(accessToken, authConfig.jwtSecret);
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
}
module.exports = new AuthService();
