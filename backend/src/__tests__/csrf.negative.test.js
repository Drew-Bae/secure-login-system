const request = require("supertest");
const app = require("../app"); // adjust if your express app export differs

describe("CSRF protection (negative)", () => {
  it("rejects POST /api/auth/login when CSRF header is missing", async () => {
    // This should fail CSRF before checking credentials,
    // so we can send any payload.
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "test@example.com", password: "whatever" });

    expect(res.status).toBe(403);
  });
});
