const { JsonWebTokenError } = require("jsonwebtoken");

const exceptionHandler = (err, req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }
  if (err.code === "ER_DUP_ENTRY") {
    return res.error(400, null, "Email already existed");
  }
  console.log(err);
  if (err instanceof JsonWebTokenError) {
    return res.error(401, null, "Unauthorized");
  }
  const message = err.message || "Internal Server Error";
  const status = err.statusCode || 500;
  const error = process.env.NODE_ENV === "development" ? err.stack : undefined;
  res.error(status, error, message);
};

module.exports = exceptionHandler;
