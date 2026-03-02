const notFoundHandler = (req, res) => {
  res.error(404, "Resource not found");
};
module.exports = notFoundHandler;
