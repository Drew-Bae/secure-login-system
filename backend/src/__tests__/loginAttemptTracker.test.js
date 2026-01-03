const request = require("supertest");
const express = require("express");

// Force-enable the tracker in test mode
beforeAll(() => {
  process.env.FORCE_LOGIN_TRACKER = "true";
  process.env.LOGIN_EMAIL_IP_MAX = "3"; // keep test fast
});

afterAll(() => {
  delete process.env.FORCE_LOGIN_TRACKER;
  delete process.env.LOGIN_EMAIL_IP_MAX;
});

describe("loginAttemptTracker (email+ip)", () => {
  it("returns 429 after exceeding attempts for same email+ip", async () => {
    // IMPORTANT: require inside test so env vars are set first
    const { loginAttemptTracker, __resetForTests } = require("../middleware/loginAttemptTracker");
    __resetForTests();

    // Minimal app: no DB, no CSRF, just the limiter
    const app = express();
    app.use(express.json());
    app.post("/login", loginAttemptTracker, (req, res) => res.status(200).json({ ok: true }));

    // 3 allowed
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post("/login")
        .set("x-forwarded-for", "1.2.3.4") // stable IP
        .send({ email: "limit@test.com", password: "x" })
        .expect(200);
    }

    // 4th blocked
    await request(app)
      .post("/login")
      .set("x-forwarded-for", "1.2.3.4")
      .send({ email: "limit@test.com", password: "x" })
      .expect(429);
  });
});
