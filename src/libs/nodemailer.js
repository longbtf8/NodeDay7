const mailConfig = require("@/config/mail.config");
const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: mailConfig.fromAddress,
    pass: mailConfig.appPassword,
  },
});
module.exports = { transporter };
