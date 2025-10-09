// server.js — MTOS Auth + Wasabi Storage (Neon for users only)

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { randomUUID } = require("crypto");
const { Pool } = require("pg");
const { S3Client, ListObjectsV2Command, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// ---- Config ----
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const API_KEY = process.env.GLOBAL_API_KEY;

// ---- PostgreSQL ----
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ---- Wasabi S3 Client ----
const s3 = new S3Client({
  region: process.env.WASABI_REGION,
  endpoint: `https://${process.env.WASABI_ENDPOINT}`,
  credentials: {
    accessKeyId: process.env.WASABI_ACCESS_KEY_ID,
    secretAccessKey: process.env.WASABI_SECRET_ACCESS_KEY,
  },
});
const BUCKET = process.env.WASABI_BUCKET;
const ONE_GB = 1024 * 1024 * 1024; // 1GB limit per user

// ---- Middleware ----
function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"];
  if (!key || key !== API_KEY) return res.status(401).json({ error: "Invalid API key" });
  next();
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---- Validators ----
const emailPattern = /^[a-zA-Z0-9]+@mtos-org\.com$/;
const signupRules = [
  body("name").trim().isLength({ min: 2 }),
  body("mobile").matches(/^[0-9]{7,15}$/),
  body("dob").isISO8601(),
  body("country").isLength({ min: 2 }),
  body("email").matches(emailPattern),
  body("password").isLength({ min: 8 }),
];

// ---- JWT Helper ----
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

// ---- Neon Auth Routes ----
app.get("/v1/health", async (_req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ ok: true, db_time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ error: "DB connection failed" });
  }
});

app.post("/v1/auth/signup", requireApiKey, signupRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

  const { name, mobile, dob, country, email, password } = req.body;
  try {
    const existing = await pool.query("SELECT id FROM users WHERE email=$1 OR mobile=$2", [email.toLowerCase(), mobile]);
    if (existing.rows.length > 0) return res.status(409).json({ error: "User already exists" });

    const passwordHash = bcrypt.hashSync(password, 12);
    const userId = randomUUID();
    await pool.query(
      `INSERT INTO users (id, name, mobile, dob, country, email, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, name, mobile, dob, country, email.toLowerCase(), passwordHash]
    );

    const token = signToken({ id: userId, email });
    res.status(201).json({ user: { id: userId, name, mobile, dob, country, email }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database insert failed" });
  }
});

app.post("/v1/auth/login", requireApiKey, async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid email or password" });

    const user = result.rows[0];
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });

    const token = signToken(user);
    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ error: "Database query failed" });
  }
});

app.get("/v1/auth/me", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, mobile, dob, country, email FROM users WHERE id=$1", [req.user.sub]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch {
    res.status(500).json({ error: "Database read failed" });
  }
});

// ---- Wasabi Helpers ----
function userFolder(email) {
  return email.toLowerCase().replace(/[^a-z0-9_.-]/g, "_") + "/";
}

async function getUserUsage(email) {
  const prefix = userFolder(email);
  let continuationToken = undefined;
  let total = 0;
  do {
    const res = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix, ContinuationToken: continuationToken }));
    if (res.Contents) total += res.Contents.reduce((sum, obj) => sum + (obj.Size || 0), 0);
    continuationToken = res.NextContinuationToken;
  } while (continuationToken);
  return total;
}

// ---- Wasabi Storage Routes ----
app.get("/v1/storage/usage", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const used = await getUserUsage(req.user.email);
    res.json({ bytesUsed: used, bytesLimit: ONE_GB });
  } catch {
    res.status(500).json({ error: "Usage failed" });
  }
});

app.post("/v1/storage/presign/put", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const { filename, size = 0, contentType = "application/octet-stream" } = req.body;
    if (!filename) return res.status(422).json({ error: "filename required" });

    const used = await getUserUsage(req.user.email);
    if (used + Number(size) > ONE_GB) return res.status(413).json({ error: "1GB limit reached" });

    const key = `${userFolder(req.user.email)}${Date.now()}_${filename.replace(/[^\w.\-]/g, "_")}`;
    const cmd = new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: contentType });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 300 }); // 5 min
    res.json({ url, key, headers: { "Content-Type": contentType } });
  } catch {
    res.status(500).json({ error: "Presign failed" });
  }
});

app.get("/v1/storage/presign/get", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const key = req.query.key;
    if (!key) return res.status(422).json({ error: "key required" });
    if (!key.startsWith(userFolder(req.user.email))) return res.status(403).json({ error: "Forbidden" });

    const cmd = new GetObjectCommand({ Bucket: BUCKET, Key: key });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 300 });
    res.json({ url });
  } catch {
    res.status(500).json({ error: "Presign failed" });
  }
});

app.get("/v1/storage/list", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const prefix = userFolder(req.user.email);
    const cmd = new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix });
    const r = await s3.send(cmd);
    const items = (r.Contents || []).map(o => ({ key: o.Key, size: o.Size, lastModified: o.LastModified }));
    res.json({ items });
  } catch {
    res.status(500).json({ error: "List failed" });
  }
});

app.delete("/v1/storage/delete", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) return res.status(422).json({ error: "key required" });
    if (!key.startsWith(userFolder(req.user.email))) return res.status(403).json({ error: "Forbidden" });
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Delete failed" });
  }
});

// ---- Start Server ----
app.listen(PORT, HOST, () => {
  console.log(`✅ MTOS Auth + Wasabi Storage running at http://${HOST}:${PORT}`);
});

