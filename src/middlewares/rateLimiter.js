const createRateLimiter = (config) => {
  const { windowMs, maxRequests, message } = config;
  //lưu trữ thông tin
  const client = {};
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress;
    const currentTime = Date.now();

    if (!client[ip] || currentTime > client[ip].resetTime) {
      client[ip] = {
        count: 0,
        resetTime: windowMs + currentTime,
      };
    }
    client[ip].count++;
    if (client[ip].count > maxRequests) {
      return res.status(429).json({
        error: message,
      });
    }
    next();
  };
};
const apiRateLimiter = createRateLimiter({
  windowMs: 60000,
  maxRequests: 100,
  message: "Too many requests",
});
module.exports = { createRateLimiter, apiRateLimiter };
