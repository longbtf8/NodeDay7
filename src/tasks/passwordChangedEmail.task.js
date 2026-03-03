const mailService = require("../services/mail.service");

async function passwordChangedEmail(payload) {
  await mailService.passwordChangedEmail(payload);
}
module.exports = passwordChangedEmail;
