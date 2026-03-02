const mailConfig = {
  fromAddress: process.env.MAIL_FROM_ADDRESS,
  fromName: process.env.MAIL_FROM_NAME,
  appPassword: process.env.MAIL_APP_PASSWORD,
};

module.exports = mailConfig;
