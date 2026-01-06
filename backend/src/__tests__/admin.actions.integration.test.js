const request = require("supertest");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const bcrypt = require("bcrypt");

const app = require("../app");
const User = require("../models/User");
const AuditEvent = require("../models/AuditEvent");

let mongo;

async function mintCsrf(agent) {
  const res = await agent.get("/api/auth/csrf").expect(200);
  const csrfToken = res.body.csrfToken;
  if (!csrfToken) throw new Error("CSRF token missing from /api/auth/csrf");
  return csrfToken;
}

describe("Admin actions integration", () => {
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
    await mongoose.connection.db.dropDatabase();
  });

  test("admin can lock/unlock user and revoke sessions", async () => {
    const userPw = await bcrypt.hash("Password123!", 10);
    const adminPw = await bcrypt.hash("Password123!", 10);

    const user = await User.create({ email: "user@test.com", password: userPw, role: "user" });
    await User.create({ email: "admin@test.com", password: adminPw, role: "admin" });

    // user session
    const userAgent = request.agent(app);
    const csrfU = await mintCsrf(userAgent);
    await userAgent
      .post("/api/auth/login")
      .set("x-csrf-token", csrfU)
      .set("x-device-id", "device-user")
      .send({ email: "user@test.com", password: "Password123!" })
      .expect(200);

    await userAgent.get("/api/auth/me").expect(200);

    // admin session
    const adminAgent = request.agent(app);
    const csrfA = await mintCsrf(adminAgent);
    await adminAgent
      .post("/api/auth/login")
      .set("x-csrf-token", csrfA)
      .set("x-device-id", "device-admin")
      .send({ email: "admin@test.com", password: "Password123!" })
      .expect(200);

    // lock user
    const csrfLock = await mintCsrf(adminAgent);
    await adminAgent
      .post(`/api/admin/users/${user._id.toString()}/lock`)
      .set("x-csrf-token", csrfLock)
      .send({ minutes: 60 })
      .expect(200);

    const locked = await User.findById(user._id);
    expect(locked.lockoutUntil).toBeTruthy();
    expect(new Date(locked.lockoutUntil).getTime()).toBeGreaterThan(Date.now());

    // unlock user
    const csrfUnlock = await mintCsrf(adminAgent);
    await adminAgent
      .post(`/api/admin/users/${user._id.toString()}/unlock`)
      .set("x-csrf-token", csrfUnlock)
      .send({})
      .expect(200);

    const unlocked = await User.findById(user._id);
    expect(unlocked.lockoutUntil).toBeFalsy();

    // revoke user sessions (admin)
    const csrfRevoke = await mintCsrf(adminAgent);
    await adminAgent
      .post(`/api/admin/users/${user._id.toString()}/revoke-sessions`)
      .set("x-csrf-token", csrfRevoke)
      .send({})
      .expect(200);

    // user session should now be invalid
    await userAgent.get("/api/auth/me").expect(401);

    // audit events should exist
    const events = await AuditEvent.find({ targetUserId: user._id }).lean();
    const actions = events.map((e) => e.action);
    expect(actions).toEqual(expect.arrayContaining(["ADMIN_LOCK_USER", "ADMIN_UNLOCK_USER", "ADMIN_REVOKE_SESSIONS"]));
  });
});
