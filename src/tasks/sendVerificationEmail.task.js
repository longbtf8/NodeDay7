const mailService = require("../services/mail.service");

async function sendVerificationEmail(payload) {
  await mailService.sendVerificationEmail(payload);
}
module.exports = sendVerificationEmail;
