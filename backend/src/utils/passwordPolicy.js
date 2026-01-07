const bcrypt = require("bcrypt");

// "Standard" password policy for this project:
// - >= 12 characters
// - at least 1 uppercase, 1 lowercase, 1 number, 1 special character
// - no whitespace
// - should not contain the user's email local-part (basic personal-info check)
const PASSWORD_MIN_LENGTH = 12;

function validatePasswordComplexity(password, opts = {}) {
  const pw = String(password || "");
  const email = String(opts.email || "").toLowerCase().trim();

  if (pw.length < PASSWORD_MIN_LENGTH) {
    return {
      ok: false,
      message:
        "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
    };
  }

  if (/\s/.test(pw)) {
    return { ok: false, message: "Password must not contain spaces." };
  }

  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSpecial = /[^A-Za-z0-9]/.test(pw);

  if (!hasLower || !hasUpper || !hasDigit || !hasSpecial) {
    return {
      ok: false,
      message:
        "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
    };
  }

  // Basic personal-info check: don't include the email local-part if it is meaningful.
  if (email && email.includes("@")) {
    const local = email.split("@")[0];
    if (local && local.length >= 3) {
      const escaped = local.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(escaped, "i");
      if (re.test(pw)) {
        return { ok: false, message: "Password must not contain your email or username." };
      }
    }
  }

  return { ok: true };
}

async function isReusedPassword(user, candidatePassword) {
  if (!user) return false;
  const hashes = [];
  if (user.password) hashes.push(user.password);
  if (Array.isArray(user.passwordHistory)) {
    hashes.push(...user.passwordHistory.filter(Boolean));
  }

  for (const h of hashes) {
    try {
      const same = await bcrypt.compare(String(candidatePassword), h);
      if (same) return true;
    } catch {
      // ignore bad hash
    }
  }
  return false;
}

function pushPasswordHistory(user, previousHash) {
  if (!user || !previousHash) return;
  const hist = Array.isArray(user.passwordHistory) ? user.passwordHistory : [];

  // keep most-recent first, dedupe, cap at 5
  const next = [previousHash, ...hist]
    .filter(Boolean)
    .filter((v, i, arr) => arr.indexOf(v) === i)
    .slice(0, 5);

  user.passwordHistory = next;
}

module.exports = {
  PASSWORD_MIN_LENGTH,
  validatePasswordComplexity,
  isReusedPassword,
  pushPasswordHistory,
};
