const authConfig = require("@/config/auth");
const mailConfig = require("@/config/mail.config");
const { transporter } = require("@/libs/nodemailer");
const jwt = require("jsonwebtoken");
const { generateVerificationLink } = require("./auth.service");
class MailService {
  async sendVerificationEmail(user) {
    const { fromAddress, fromName } = mailConfig;

    const verificationLink = generateVerificationLink(user);
    const info = await transporter.sendMail({
      from: `"${fromName}" <${fromAddress}>`,
      to: user.email,
      subject: "Verification",
      html: `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xác minh email của bạn</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.5; color: #1a1a1a; margin: 0; padding: 0; -webkit-font-smoothing: antialiased;">
    <div style="max-width: 400px; margin: 0 auto; padding: 20px;">
        
        <h2 style="margin-top: 0; margin-bottom: 20px; font-size: 24px; font-weight: 600;">Xác minh email của bạn</h2>
        
        <p style="margin: 0 0 10px 0;">Chào bạn,</p>
        
        <p style="margin: 0 0 20px 0;">Cảm ơn bạn đã đăng ký tài khoản. Vui lòng nhấp vào nút bên dưới để xác minh địa chỉ email của bạn:</p>
        
        <!-- BUTTON LINK - THAY THẾ [VERIFICATION_LINK] BẰNG LINK THỰC TẾ -->
        <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; background-color: #0066cc; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 500; margin: 0 0 20px 0;">Xác minh email</a>
        
        <p style="margin: 0 0 10px 0;">Hoặc sao chép và dán link này vào trình duyệt:</p>
        
        <!-- TEXT LINK - THAY THẾ [VERIFICATION_LINK] BẰNG LINK THỰC TẾ -->
        <p style="margin: 0 0 20px 0; word-break: break-all;">
            <a href="${verificationLink}" style="color: #0066cc; text-decoration: underline;">${verificationLink}</a>
        </p>
        
        <p style="margin: 0 0 30px 0; font-size: 14px; color: #666666;">Link này sẽ hết hạn sau 24 giờ.</p>
        
        <hr style="border: none; border-top: 1px solid #eaeaea; margin: 20px 0;">
        
        <div style="font-size: 14px; color: #666666;">
            <p style="margin: 0 0 10px 0;">Nếu bạn không yêu cầu email này, vui lòng bỏ qua.</p>
            <p style="margin: 0;">© 2024 Công ty của bạn. All rights reserved.</p>
        </div>
        
    </div>
</body>
</html>`,
    });
  }
}
module.exports = new MailService();
