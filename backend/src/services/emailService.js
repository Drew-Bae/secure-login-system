const { Resend } = require("resend");

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendPasswordResetEmail({ to, resetUrl }) {
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) {
    console.log(`[DEV] Password reset link for ${to}: ${resetUrl}`);
    return;
  }

  try {
    await resend.emails.send({
      from: process.env.EMAIL_FROM,
      to,
      subject: "Reset your password",
      html: `
        <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;">
          <h2>Password Reset</h2>
          <p>You requested a password reset for your account.</p>
          <p style="margin: 24px 0;">
            <a href="${resetUrl}" style="
              background:#111;
              color:#fff;
              padding:10px 14px;
              border-radius:8px;
              text-decoration:none;
              display:inline-block;
            ">
              Reset Password
            </a>
          </p>
          <p>If the button doesn't work, copy and paste this link:</p>
          <p><a href="${resetUrl}">${resetUrl}</a></p>
          <p style="margin-top:24px;color:#666;">
            If you did not request this, you can safely ignore this email.
          </p>
        </div>
      `,
    });
  } catch (err) {
    console.error("Resend email error:", err);
    throw err;
  }
}

module.exports = { sendPasswordResetEmail };
