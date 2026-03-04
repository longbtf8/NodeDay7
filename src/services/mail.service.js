const authConfig = require("@/config/auth");
const mailConfig = require("@/config/mail.config");
const { transporter } = require("@/libs/nodemailer");
const jwt = require("jsonwebtoken");
const authService = require("./auth.service");
const ejs = require("ejs");
const path = require("path");

class MailService {
  getTemplatePath(template) {
    const templatePath = path.join(
      __dirname,
      "..",
      "resource",
      "mail",
      `${template.replace("ejs", "")}.ejs`,
    );
    return templatePath;
  }
  async send(options) {
    const { template, templateData, ...restOptions } = options;

    const templatePath = this.getTemplatePath(template);
    const html = await ejs.renderFile(templatePath, templateData);
    const result = await transporter.sendMail({ ...restOptions, html });
    return result;
  }

  //send verification email
  async sendVerificationEmail(user) {
    const { fromAddress, fromName } = mailConfig;

    const verificationLink = authService.generateVerificationLink(user);
    await this.send({
      from: `"${fromName}" <${fromAddress}>`,
      to: user.email,
      template: "auth/verificationEmail",
      templateData: {
        verificationLink,
      },
      subject: "Verification",
    });
  }
  //send password change email
  async sendPasswordChangeEmail(user) {
    const { fromAddress, fromName } = mailConfig;

    await this.send({
      from: `"${fromName}" <${fromAddress}>`,
      to: user.email,
      template: "auth/sendPasswordChangeEmail",
      templateData: {
        changeTime: new Date().toLocaleString(),
      },
      subject: "Thông báo đổi mật khẩu ",
    });
  }
}
module.exports = new MailService();
