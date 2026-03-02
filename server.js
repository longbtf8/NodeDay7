require("dotenv").config();
require("module-alias/register");
const exceptionHandler = require("@/middlewares/exceptionHandler");
const notFoundHandler = require("@/middlewares/notFoundHandler");
const { apiRateLimiter } = require("@/middlewares/rateLimiter");
const responseFormat = require("@/middlewares/responseFormat");
const express = require("express");
const app = express();
const port = 3000;
const apiRouter = require("@/routes/index");

app.use(express.json());
app.use(responseFormat);
app.use(apiRateLimiter);
app.get("/test-success", (req, res) => {
  console.log(req.socket.remoteAddress);
  res.success({ message: "Hello World" });
});
app.get("/test-error", (req, res) => {
  //   res.write("Writing...");
  throw new Error("Test exception");
});
app.use("/api", apiRouter);

app.use(notFoundHandler);
app.use(exceptionHandler);
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
