const express = require("express");
const router = express.Router();
const fs = require("node:fs");
const basePath = "./src/routes";
const postFix = ".route.js";
fs.readdirSync(basePath)
  .filter((_filename) => _filename.endsWith(postFix))
  .forEach((fileName) => {
    const resourceName = fileName.replace(postFix, "");
    router.use(`/${resourceName}`, require(`./${fileName}`));
  });

module.exports = router;
