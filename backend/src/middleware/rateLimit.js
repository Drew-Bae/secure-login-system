const rateLimit = require("express-rate-limit");

// Limit repeated requests to auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 auth requests per window
  standardHeaders: true, // RateLimit-* headers
  legacyHeaders: false,  // disable X-RateLimit-* headers
  message: {
    message: "Too many auth attempts. Please try again later.",
  },
});

module.exports = { authLimiter };
