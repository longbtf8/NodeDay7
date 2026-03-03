const { readdirSync } = require("node:fs");

const jobs = readdirSync(__dirname)
  .filter((fileName) => fileName !== "index.js")
  .reduce((obj, fileName) => {
    const type = fileName.replace(".task.js", "");
    return {
      ...obj,
      [type]: require(`./${fileName}`),
    };
  }, {});
module.exports = jobs;
