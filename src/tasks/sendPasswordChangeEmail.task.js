const mailService = require("../services/mail.service");

async function sendPasswordChangeEmail(payload) {
  await mailService.sendPasswordChangeEmail(payload);
}
module.exports = sendPasswordChangeEmail;
