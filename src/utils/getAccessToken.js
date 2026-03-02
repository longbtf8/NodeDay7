const getAccessToken = (req) => {
  const accessToken = req.headers?.authorization?.slice(6).trim();
  return accessToken;
};
module.exports = getAccessToken;
