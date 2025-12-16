async function sendPasswordResetEmail({ to, resetUrl }) {
  // Step 3 will implement SMTP (Nodemailer + Zoho).
  // For now, log the reset URL so you can test end-to-end.
  console.log(`[DEV] Password reset link for ${to}: ${resetUrl}`);
}

module.exports = { sendPasswordResetEmail };
