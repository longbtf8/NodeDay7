const bcrypt = require("bcrypt");
const authService = require("@/services/auth.service");
const authConfig = require("@/config/auth");
const authModel = require("@/models/auth.model");
const revokedModel = require("@/models/revokedToken.model");
const { isValidEmail, isValidPassword } = require("@/utils/validator");
const getAccessToken = require("@/utils/getAccessToken");
const db = require("@/config/database");
const mailService = require("@/services/mail.service");
const constants = require("@/config/constants");
const queueService = require("@/services/queue.service");

const register = async (req, res) => {
  const email = req.body?.email;
  const password = req.body?.password;

  if (!email) {
    return res.error(400, null, "Email không được để trống");
  }

  if (!password) {
    return res.error(400, null, "Mật khẩu không được để trống");
  }

  if (!isValidEmail(email)) {
    return res.error(400, null, "Email không hợp lệ");
  }

  if (!isValidPassword(password)) {
    return res.error(400, null, "Mật khẩu phải có ít nhất 6 ký tự");
  }
  const hashedPassword = await bcrypt.hash(password, authConfig.saltRounds);

  // Kiểm tra email tồn tại
  const existingUser = await authModel.getInfoUserLogin(email);
  if (existingUser) {
    return res.error(400, null, "Email đã tồn tại");
  }

  const insertId = await authModel.registerUser(email, hashedPassword);

  const accessToken = await authService.signAccessToken(insertId);

  const user = {
    id: insertId,
    email,
  };
  const refreshToken = await authService.createRefreshToken(
    user,
    req.headers["user-agent"],
  );
  //send email
  await queueService.push("sendVerificationEmail", user);

  const newUser = {
    id: insertId,
    email,
    access_token: accessToken,
    refresh_token: refreshToken,
  };

  return res.success(newUser);
};
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email) return res.error(400, null, "Email không được để trống");
  if (!password) return res.error(400, null, "Mật khẩu không được để trống");
  if (!isValidEmail(email)) return res.error(400, null, "Email không hợp lệ");

  const user = await authModel.getInfoUserLogin(email);
  if (!user) {
    return res.error(401, null, "Resource not found");
  }
  const result = await bcrypt.compare(password, user.password);
  if (result) {
    if (!user.email_verified_at) {
      return res.error(constants.httpCodes.forbidden, null, {
        message: "Please verify your email.",
      });
    }
    const accessToken = await authService.signAccessToken(user.id);
    const refreshToken = await authService.createRefreshToken(
      user,
      req.headers["user-agent"],
    );
    return res.success({
      id: user.id,
      email: user.email,
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  }

  return res.error(401, null, "Unauthorized");
};
const getInfoUser = async (req, res) => {
  const user = { ...req.currentUser };
  delete user.password;
  return res.success(user);
};

const logout = async (req, res) => {
  const { accessToken, tokenPayload } = req;

  await revokedModel.logout(accessToken, tokenPayload);
  res.success(null, 204);
  return;
};
const refreshToken = async (req, res) => {
  const { refresh_token } = req.body;

  const refreshTokenDB = await authModel.selectRefreshToken(refresh_token);
  if (!refreshTokenDB) {
    return res.error(401, null, "Unauthorized");
  }

  const user = {
    id: refreshTokenDB.user_id,
  };
  // create new access & refreshToken
  const accessToken = await authService.signAccessToken(user.id);
  const refreshToken = await authService.createRefreshToken(
    user,
    req.headers["user-agent"],
  );

  // revoke old refresh Token
  authModel.updateRevokedRefreshToken(refreshTokenDB);
  res.success(
    {
      access_token: accessToken,
      refresh_token: refreshToken,
    },
    200,
  );
};

const verifyEmail = async (req, res) => {
  const { token } = req.body;
  const [error, data] = await authService.verifyEmail(token);
  if (error) {
    return res.error(constants.forbidden, null, { message: "Invalid token" });
  }
  return res.success({ message: "Verified." });
};

const changePassword = async (req, res) => {
  const { password, new_password, confirm_password } = req.body;
  if (!new_password || !confirm_password) {
    return res.error(constants.httpCodes.badRequest, null, {
      message: "Vui lòng nhập đủ cách trường passWord",
    });
  }
  const [err] = await authService.changePassword(
    req.currentUser,
    password,
    new_password,
    confirm_password,
  );
  if (err.error) {
    return res.error(constants.httpCodes.unprocessableEntity, null, {
      message: err.message,
    });
  }
  return res.success({
    message: "Đổi mật khẩu thành công ",
  });
};
module.exports = {
  register,
  login,
  getInfoUser,
  logout,
  refreshToken,
  verifyEmail,
  changePassword,
};
