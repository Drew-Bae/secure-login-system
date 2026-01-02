function cleanEmail(v) {
  return String(v || "")
    .trim()
    .replace(/^['"]+|['"]+$/g, "");
}

let resendClient = null;

function getResendClient() {
  // Never send real emails during tests
  if (process.env.NODE_ENV === "test") return null;

  // If env vars aren't configured, we'll fall back to console logging in sendPasswordResetEmail
  if (!process.env.RESEND_API_KEY) return null;

  if (!resendClient) {
    const { Resend } = require("resend");
    resendClient = new Resend(process.env.RESEND_API_KEY);
  }

  return resendClient;
}

async function sendPasswordResetEmail({ to, resetUrl }) {
  // In tests: do nothing and don't throw
  if (process.env.NODE_ENV === "test") {
    return { skipped: true };
  }

  // If not configured, keep your current dev behavior
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) {
    console.log(`[DEV] Password reset link for ${to}: ${resetUrl}`);
    return { skipped: true };
  }

  const resend = getResendClient();
  if (!resend) {
    console.log(`[DEV] Password reset link for ${to}: ${resetUrl}`);
    return { skipped: true };
  }

  const fromEmail = cleanEmail(process.env.EMAIL_FROM);
  const from = `Secure Login System <${fromEmail}>`;

  try {
    await resend.emails.send({
      from,
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

    return { sent: true };
  } catch (err) {
    console.error("Resend email error:", err);
    throw err;
  }
}

module.exports = { sendPasswordResetEmail };
