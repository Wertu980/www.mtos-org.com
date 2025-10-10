// server.js — MTOS Auth + Wasabi Storage (Neon for users only)

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { randomUUID } = require("crypto");
const { Pool } = require("pg");

const {
  S3Client,
  ListObjectsV2Command,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} = require("@aws-sdk/client-s3");
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
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---- Wasabi S3 ----
const wasabiEndpoint = process.env.WASABI_ENDPOINT.startsWith("http")
  ? process.env.WASABI_ENDPOINT
  : `https://${process.env.WASABI_ENDPOINT}`;

const s3 = new S3Client({
  region: process.env.WASABI_REGION || "ap-northeast-1",
  endpoint: wasabiEndpoint,
  credentials: {
    accessKeyId: process.env.WASABI_ACCESS_KEY_ID,
    secretAccessKey: process.env.WASABI_SECRET_ACCESS_KEY,
  },
});
const BUCKET = process.env.WASABI_BUCKET;

// ---- Constants ----
const BYTES_LIMIT = 512 * 1024 * 1024; // 512 MB
const CATEGORY_TO_SUBDIR = {
  "media-photo": "Media/Photo/",
  "media-video": "Media/Video/",
  "email": "Email/",
  "apps": "Apps/",
  "other": "Other/",
};

// ---- Middleware ----
function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"];
  if (!key || key !== API_KEY)
    return res.status(401).json({ error: "Invalid API key" });
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

// ---- Helpers ----
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function sanitizeEmail(email) {
  return email.toLowerCase().replace(/[^a-z0-9_.-]/g, "_");
}

function userPrefix(email) {
  return `users/${sanitizeEmail(email)}/`;
}

async function ensureUserSpace(email) {
  const root = userPrefix(email);
  const subdirs = [
    "Media/Photo/",
    "Media/Video/",
    "Email/",
    "Apps/",
    "Other/",
  ];
  try {
    await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: root + ".keep" }));
  } catch {
    const all = [root, ...subdirs.map((s) => root + s)].map((p) => p + ".keep");
    for (const key of all) {
      try {
        await s3.send(
          new PutObjectCommand({
            Bucket: BUCKET,
            Key: key,
            Body: new Uint8Array(0),
            ContentType: "application/octet-stream",
          })
        );
      } catch (e) {
        console.warn("ensureUserSpace error:", key, e.message);
      }
    }
  }
}

async function getUserUsage(email) {
  const prefix = userPrefix(email);
  let token;
  let total = 0;
  do {
    const r = await s3.send(
      new ListObjectsV2Command({
        Bucket: BUCKET,
        Prefix: prefix,
        ContinuationToken: token,
      })
    );
    if (r.Contents)
      total += r.Contents.reduce((sum, obj) => sum + (obj.Size || 0), 0);
    token = r.NextContinuationToken;
  } while (token);
  return total;
}

// ---- Auth Routes ----
app.get("/v1/health", async (_req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ ok: true, db_time: result.rows[0].now });
  } catch {
    res.status(500).json({ error: "DB connection failed" });
  }
});

app.post("/v1/auth/signup", requireApiKey, signupRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(422).json({ errors: errors.array() });

  const { name, mobile, dob, country, email, password } = req.body;
  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email=$1 OR mobile=$2",
      [email.toLowerCase(), mobile]
    );
    if (existing.rows.length > 0)
      return res.status(409).json({ error: "User already exists" });

    const hash = bcrypt.hashSync(password, 12);
    const userId = randomUUID();
    await pool.query(
      `INSERT INTO users (id, name, mobile, dob, country, email, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [userId, name, mobile, dob, country, email.toLowerCase(), hash]
    );

    await ensureUserSpace(email);
    const token = signToken({ id: userId, email });
    res.status(201).json({ user: { id: userId, name, email }, token });
  } catch (err) {
    console.error("Signup error:", err.message);
    res.status(500).json({ error: "Database insert failed" });
  }
});

app.post("/v1/auth/login", requireApiKey, async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [
      email.toLowerCase(),
    ]);
    if (result.rows.length === 0)
      return res.status(401).json({ error: "Invalid email or password" });

    const user = result.rows[0];
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok)
      return res.status(401).json({ error: "Invalid email or password" });

    await ensureUserSpace(user.email);
    const token = signToken(user);
    res.json({
      user: { id: user.id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    res.status(500).json({ error: "Database query failed" });
  }
});

app.get("/v1/auth/me", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, name, email, country FROM users WHERE id=$1",
      [req.user.sub]
    );
    if (r.rows.length === 0)
      return res.status(404).json({ error: "User not found" });
    res.json({ user: r.rows[0] });
  } catch {
    res.status(500).json({ error: "Database read failed" });
  }
});

// ---- Storage Routes ----
app.get("/v1/storage/usage", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const used = await getUserUsage(req.user.email);
    res.json({ bytesUsed: used, bytesLimit: BYTES_LIMIT });
  } catch {
    res.status(500).json({ error: "Usage failed" });
  }
});

app.post("/v1/storage/presign/put", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const { filename, size = 0, contentType = "application/octet-stream", category } = req.body;
    if (!filename) return res.status(422).json({ error: "filename required" });

    const used = await getUserUsage(req.user.email);
    if (used + Number(size) > BYTES_LIMIT) {
      const remaining = Math.max(0, BYTES_LIMIT - used);
      return res.status(413).json({
        error: "Storage full (512 MB limit reached). Please delete files to free space.",
        used_bytes: used,
        limit_bytes: BYTES_LIMIT,
        remaining_bytes: remaining
      });
    }

    await ensureUserSpace(req.user.email);
    const base = userPrefix(req.user.email);
    const sub = CATEGORY_TO_SUBDIR[category] || "";
    const safe = filename.replace(/[^\w.\-]/g, "_");
    const key = `${base}${sub}${Date.now()}_${safe}`;

    const cmd = new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      ContentType: contentType,
    });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 300 });
    res.json({ url, key, headers: { "Content-Type": contentType } });
  } catch (err) {
    console.error("Presign failed:", err.message);
    res.status(500).json({ error: "Presign failed" });
  }
});

app.get("/v1/storage/list", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const prefix = userPrefix(req.user.email);
    const r = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix }));
    const items = (r.Contents || [])
      .filter((o) => !o.Key.endsWith(".keep"))
      .map((o) => ({ key: o.Key, size: o.Size, lastModified: o.LastModified }));
    res.json({ items });
  } catch {
    res.status(500).json({ error: "List failed" });
  }
});

app.delete("/v1/storage/delete", requireApiKey, authMiddleware, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) return res.status(422).json({ error: "key required" });
    if (!key.startsWith(userPrefix(req.user.email)))
      return res.status(403).json({ error: "Forbidden" });
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Delete failed" });
  }
});

// ---- Start ----
app.listen(PORT, HOST, () => {
  console.log(`✅ MTOS Auth + Wasabi Storage running at http://${HOST}:${PORT}`);
});