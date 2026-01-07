const request = require("supertest");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = require("../app");
const User = require("../models/User");
const StepUpChallenge = require("../models/StepUpChallenge");
const TrustedDevice = require("../models/TrustedDevice");
const { hashToken } = require("../utils/stepUpTokens");

let mongo;

async function mintCsrf(agent) {
  const res = await agent.get("/api/auth/csrf").expect(200);
  const csrfToken = res.body.csrfToken;
  if (!csrfToken) throw new Error("CSRF token missing from /api/auth/csrf");
  return csrfToken;
}

function makePreAuthToken(userId) {
  return jwt.sign({ userId, type: "preauth" }, process.env.PREAUTH_JWT_SECRET, { expiresIn: "5m" });
}

describe("Step-up verification integration", () => {
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

  test("POST /api/auth/verify-stepup rejects expired token", async () => {
    const agent = request.agent(app);

    const password = await bcrypt.hash("Password123!", 10);
    const user = await User.create({ email: "user@test.com", password, role: "user" });

    const deviceId = "device-stepup-1";
    const rawToken = "token-expired-123";
    await StepUpChallenge.create({
      userId: user._id,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() - 60 * 1000), // expired 1 minute ago
      deviceId,
      ip: "127.0.0.1",
      userAgent: "jest",
    });

    const csrf = await mintCsrf(agent);
    const preAuthToken = makePreAuthToken(user._id.toString());

    await agent
      .post("/api/auth/verify-stepup")
      .set("x-csrf-token", csrf)
      .set("x-device-id", deviceId)
      .send({ token: rawToken, preAuthToken })
      .expect(400);
  });

  test("POST /api/auth/verify-stepup blocks compromised device", async () => {
    const agent = request.agent(app);

    const password = await bcrypt.hash("Password123!", 10);
    const user = await User.create({ email: "user@test.com", password, role: "user" });

    const deviceId = "device-stepup-2";

    // Mark device as compromised
    await TrustedDevice.create({
      userId: user._id,
      deviceId,
      compromisedAt: new Date(),
      compromisedReason: "lost_device",
      tokenVersion: 0,
      trusted: false,
    });

    const rawToken = "token-valid-123";
    await StepUpChallenge.create({
      userId: user._id,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // valid 10m
      deviceId,
      ip: "127.0.0.1",
      userAgent: "jest",
    });

    const csrf = await mintCsrf(agent);
    const preAuthToken = makePreAuthToken(user._id.toString());

    const res = await agent
      .post("/api/auth/verify-stepup")
      .set("x-csrf-token", csrf)
      .set("x-device-id", deviceId)
      .send({ token: rawToken, preAuthToken })
      .expect(401);

    expect(res.body?.message).toMatch(/compromised/i);
  });

  test("POST /api/auth/verify-stepup success sets auth cookie", async () => {
    const agent = request.agent(app);

    const password = await bcrypt.hash("Password123!", 10);
    const user = await User.create({ email: "user@test.com", password, role: "user" });

    const deviceId = "device-stepup-3";

    // optional: create a normal device record
    await TrustedDevice.create({
      userId: user._id,
      deviceId,
      trusted: false,
      tokenVersion: 0,
    });

    const rawToken = "token-valid-success-123";
    await StepUpChallenge.create({
      userId: user._id,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      deviceId,
      ip: "127.0.0.1",
      userAgent: "jest",
    });

    const csrf = await mintCsrf(agent);
    const preAuthToken = makePreAuthToken(user._id.toString());

    const res = await agent
      .post("/api/auth/verify-stepup")
      .set("x-csrf-token", csrf)
      .set("x-device-id", deviceId)
      .send({ token: rawToken, preAuthToken })
      .expect(200);

    const setCookie = res.headers["set-cookie"] || [];
    expect(setCookie.join(";")).toMatch(/token=/);
  });


  test("Login does not bypass step-up by retrying without verification", async () => {
    const agent = request.agent(app);

    const password = await bcrypt.hash("Password123!", 10);
    // Make the account older than the new-account grace window
    const user = await User.create({
      email: "user2@test.com",
      password,
      role: "user",
      createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000),
    });

    const csrf = await mintCsrf(agent);

    const deviceId = "device-stepup-bypass-1";

    // First login should require step-up (new device)
    const res1 = await agent
      .post("/api/auth/login")
      .set("x-csrf-token", csrf)
      .set("x-device-id", deviceId)
      .send({ email: user.email, password: "Password123!" })
      .expect(200);

    expect(res1.body?.stepUpRequired).toBe(true);

    // Second login attempt (same conditions) should STILL require step-up
    const res2 = await agent
      .post("/api/auth/login")
      .set("x-csrf-token", csrf)
      .set("x-device-id", deviceId)
      .send({ email: user.email, password: "Password123!" })
      .expect(200);

    expect(res2.body?.stepUpRequired).toBe(true);

    const setCookie = (res2.headers["set-cookie"] || []).join(";");
    expect(setCookie).not.toMatch(/token=/);
  });
});
