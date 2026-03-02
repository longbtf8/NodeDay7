const userService = require("@/services/user.service");
const findAll = async (req, res) => {
  const page = +req.query.page || 1;
  let limit = +req.query.limit || 20;

  // Validate and cap limit
  if (limit > 500) {
    limit = 500;
  } else if (limit < 1) {
    limit = 20;
  }

  const users = await userService.pagination(page, limit, {
    email: req.query.email,
  });

  if (users) {
    return res.success(users);
  }
  return res.error(404, null, "Not Found");
};
const findEmail = async (req, res) => {
  const email = String(req.query.q);
  if (!email) {
    return res.error(400, null, "Not Found");
  }
  const users = await userService.findUserAsEmail(email, req.currentUser.id);
  if (users) {
    return res.success(users);
  }
  return res.error(404, null, "Not Found");
};
module.exports = { findAll, findEmail };
