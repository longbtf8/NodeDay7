const mysql = require("mysql2/promise");
const fs = require("node:fs");
// Create the connection pool. The pool-specific settings are the defaults
const db = mysql.createPool({
  host:
    process.env.DB_HOST || "gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
  user: process.env.DB_USER || "4KkC5ft8jeFWs9e.root",
  password: process.env.DB_PASS || "NBXTwbpK7hwEcnzq",
  port: process.env.DB_PORT || 4000,
  database: process.env.DB_NAME || "todo_dev",
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10,
  idleTimeout: 60000,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  ssl: {
    ca: fs.readFileSync(__dirname + "/isrgrootx1.pem"),
    rejectUnauthorized: true,
  },
});

module.exports = db;
