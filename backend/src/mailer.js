const nodemailer = require('nodemailer');
const config = require('./config');
let transporter = null;
if (config.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: config.SMTP_HOST, port: config.SMTP_PORT, secure: config.SMTP_SECURE,
    auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined
  });
}
async function sendOtp(email, code) {
  if (!transporter) {
    if (config.IS_PRODUCTION) throw new Error('SMTP is required in production for recipient verification');
    console.warn(`[DEV ONLY] Vault of Troy OTP for ${email}: ${code}`);
    return;
  }
  await transporter.sendMail({
    from: config.MAIL_FROM, to: email, subject: 'Vault of Troy verification code',
    text: `Your verification code is ${code}. It expires soon. If you did not request this, ignore this email.`
  });
}
module.exports = { sendOtp };
