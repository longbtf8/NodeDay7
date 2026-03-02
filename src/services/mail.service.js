const mailConfig = require("@/config/mail.config");
const { transporter } = require("@/libs/nodemailer");

class MailService {
  async sendVerificationEmail(user) {
    const { fromAddress, fromName } = mailConfig;
    const info = await transporter.sendMail({
      from: `"${fromName}" <${fromAddress}>`,
      to: user.email,
      subject: "Verification",
      html: "<b>Hello world?</b>",
    });
    console.log(info);
  }
}
module.exports = new MailService();
