const nodemailer = require("nodemailer");

function createTransport() {
  const port = Number(process.env.SMTP_PORT || 465);
  const secure =
    String(process.env.SMTP_SECURE || "true").toLowerCase() === "true";

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

async function sendPasswordResetEmail({ to, resetUrl }) {
  // If SMTP not configured, fall back to logging (keeps dev smooth)
  const smtpConfigured =
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    process.env.EMAIL_FROM;

  if (!smtpConfigured) {
    console.log(`[DEV] Password reset link for ${to}: ${resetUrl}`);
    return;
  }

  const transporter = createTransport();

  const subject = "Reset your password";
  const text = `You requested a password reset. Use this link to reset your password:\n\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`;
  const html = `
    <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;">
      <h2>Password Reset</h2>
      <p>You requested a password reset. Click the button below to reset your password:</p>
      <p style="margin: 24px 0;">
        <a href="${resetUrl}" style="background:#111;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none;display:inline-block;">
          Reset Password
        </a>
      </p>
      <p>If the button doesn't work, copy and paste this link:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <p style="margin-top:24px;color:#666;">If you did not request this, you can ignore this email.</p>
    </div>
  `;

  // Optional: verify connection (nice for debugging on Render)
  // await transporter.verify();

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject,
    text,
    html,
  });
}

module.exports = { sendPasswordResetEmail };
