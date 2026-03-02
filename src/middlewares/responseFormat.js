function responseFormat(req, res, next) {
  res.success = (data, status = 200, passProp = {}) => {
    res.status(status).json({
      status: "success",
      data,
      ...passProp,
    });
  };
  res.paginate = ({ rows, pagination }) => {
    res.success(rows, 200, { pagination });
  };
  res.error = (status = 500, error = null, message) => {
    console.log(message, status, error);
    const payload = {
      status: "error",
      message,
    };
    if (error) {
      payload.error = error;
    }
    res.status(status).json(payload);
  };
  next();
}
module.exports = responseFormat;
