const request = require("supertest");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const bcrypt = require("bcrypt");

const app = require("../app");
const User = require("../models/User");

let mongo;

async function mintCsrf(agent) {
  const res = await agent.get("/api/auth/csrf").expect(200);
  const csrfToken = res.body.csrfToken;
  if (!csrfToken) throw new Error("CSRF token missing from /api/auth/csrf");
  return csrfToken;
}

describe("Auth integration", () => {
  beforeAll(async () => {
    process.env.JWT_SECRET = process.env.JWT_SECRET || "test_jwt_secret";
    process.env.PREAUTH_JWT_SECRET = process.env.PREAUTH_JWT_SECRET || "test_preauth_secret";
    process.env.CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

    mongo = await MongoMemoryServer.create();
    await mongoose.connect(mongo.getUri());
  });

  afterAll(async () => {
    await mongoose.disconnect();
    if (mongo) await mongo.stop();
  });

  afterEach(async () => {
    // clean between tests
    await mongoose.connection.db.dropDatabase();
  });

  test("POST /api/auth/login requires CSRF", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ email: "a@test.com", password: "pw" })
      .expect(403);
  });

  test("register -> login -> me -> logout -> me (401)", async () => {
    const agent = request.agent(app);

    // CSRF for register
    const csrf1 = await mintCsrf(agent);

    await agent
      .post("/api/auth/register")
      .set("x-csrf-token", csrf1)
      .send({ email: "user@test.com", password: "Password123!" })
      .expect(201);

    // CSRF for login
    const csrf2 = await mintCsrf(agent);

    const loginRes = await agent
      .post("/api/auth/login")
      .set("x-csrf-token", csrf2)
      .set("x-device-id", "device-test-1")
      .send({ email: "user@test.com", password: "Password123!" })
      .expect(200);

    // token cookie should be set
    const setCookie = loginRes.headers["set-cookie"] || [];
    expect(setCookie.join(";")).toMatch(/token=/);

    // /me should work
    const meRes = await agent.get("/api/auth/me").expect(200);
    expect(meRes.body.user.email).toBe("user@test.com");

    // CSRF for logout (state-changing)
    const csrf3 = await mintCsrf(agent);

    await agent
      .post("/api/auth/logout")
      .set("x-csrf-token", csrf3)
      .expect(200);

    // /me should fail now
    await agent.get("/api/auth/me").expect(401);
  });

  test("admin route is 403 for non-admin, 200 for admin", async () => {
    const userPw = await bcrypt.hash("Password123!", 10);
    const adminPw = await bcrypt.hash("Password123!", 10);

    await User.create({ email: "user@test.com", password: userPw, role: "user" });
    await User.create({ email: "admin@test.com", password: adminPw, role: "admin" });

    // non-admin agent
    const userAgent = request.agent(app);
    const csrfU = await mintCsrf(userAgent);
    await userAgent
      .post("/api/auth/login")
      .set("x-csrf-token", csrfU)
      .set("x-device-id", "device-user")
      .send({ email: "user@test.com", password: "Password123!" })
      .expect(200);

    await userAgent.get("/api/admin/login-attempts").expect(403);

    // admin agent
    const adminAgent = request.agent(app);
    const csrfA = await mintCsrf(adminAgent);
    await adminAgent
      .post("/api/auth/login")
      .set("x-csrf-token", csrfA)
      .set("x-device-id", "device-admin")
      .send({ email: "admin@test.com", password: "Password123!" })
      .expect(200);

    await adminAgent.get("/api/admin/login-attempts").expect(200);
  });

  test("logout-all revokes other active sessions", async () => {
    // Two separate browser sessions
    const agentA = request.agent(app);
    const agentB = request.agent(app);

    // Register once using agentA
    const csrfReg = await mintCsrf(agentA);
    await agentA
      .post("/api/auth/register")
      .set("x-csrf-token", csrfReg)
      .send({ email: "multi@test.com", password: "Password123!" })
      .expect(201);

    // Login on agentA
    const csrfA1 = await mintCsrf(agentA);
    await agentA
      .post("/api/auth/login")
      .set("x-csrf-token", csrfA1)
      .set("x-device-id", "device-A")
      .send({ email: "multi@test.com", password: "Password123!" })
      .expect(200);

    // Login on agentB
    const csrfB1 = await mintCsrf(agentB);
    await agentB
      .post("/api/auth/login")
      .set("x-csrf-token", csrfB1)
      .set("x-device-id", "device-B")
      .send({ email: "multi@test.com", password: "Password123!" })
      .expect(200);

    // Sanity: both are authenticated
    await agentA.get("/api/auth/me").expect(200);
    await agentB.get("/api/auth/me").expect(200);

    // Agent A revokes all sessions (increments tokenVersion + clears its cookie)
    const csrfA2 = await mintCsrf(agentA);
    await agentA
      .post("/api/auth/logout-all")
      .set("x-csrf-token", csrfA2)
      .expect(200);

    // Agent B should now be rejected because its JWT has old tokenVersion
    await agentB.get("/api/auth/me").expect(401);
  });
});
