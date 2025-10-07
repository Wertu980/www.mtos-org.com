// server.js — MTOS Auth Backend (JSON storage + API keys + versioned routes)
//
// Features:
// ✅ Auto-create ./data/user.json
// ✅ Signup / Login / Me
// ✅ Forgot / Reset password
// ✅ Global + per-app API keys
// ✅ Admin key management
// ✅ Versioned base URL (/v1)

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { nanoid } = require("nanoid");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// ---- Config
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key";
const GLOBAL_API_KEY = process.env.GLOBAL_API_KEY || "";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const BASE_API_URL = process.env.BASE_API_URL || `http://${HOST}:${PORT}/v1`;

// ---- JSON DB (auto-create folder + file)
const dataDir = path.join(__dirname, "data");
const dataFile = path.join(dataDir, "user.json");

function ensureJsonDb() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    if (!fs.existsSync(dataFile)) {
        fs.writeFileSync(
              dataFile,
                    JSON.stringify({ users: [], resetTokens: [], apiKeys: [] }, null, 2),
                          "utf-8"
                              );
                                  console.log("📄 Created data/user.json");
                                    } else {
                                        const db = readDB();
                                            let changed = false;
                                                if (!Array.isArray(db.users)) { db.users = []; changed = true; }
                                                    if (!Array.isArray(db.resetTokens)) { db.resetTokens = []; changed = true; }
                                                        if (!Array.isArray(db.apiKeys)) { db.apiKeys = []; changed = true; }
                                                            if (changed) writeDB(db);
                                                              }
                                                              }
                                                              ensureJsonDb();

                                                              // ---- DB helpers
                                                              function readDB() {
                                                                try {
                                                                    const raw = fs.readFileSync(dataFile, "utf-8");
                                                                        return JSON.parse(raw || '{"users":[],"resetTokens":[],"apiKeys":[]}');
                                                                          } catch {
                                                                              return { users: [], resetTokens: [], apiKeys: [] };
                                                                                }
                                                                                }
                                                                                function writeDB(data) {
                                                                                  const tmp = dataFile + ".tmp";
                                                                                    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf-8");
                                                                                      fs.renameSync(tmp, dataFile);
                                                                                      }

                                                                                      // ---- Validators
                                                                                      const emailPattern = /^[a-zA-Z0-9]+@mtos-org\.com$/;
                                                                                      const signupRules = [
                                                                                        body("name").trim().isLength({ min: 2, max: 100 }),
                                                                                          body("mobile").trim().matches(/^[0-9]{7,15}$/),
                                                                                            body("dob").isISO8601(),
                                                                                              body("country").trim().isLength({ min: 2, max: 56 }),
                                                                                                body("email").trim().matches(emailPattern),
                                                                                                  body("password").isLength({ min: 8 }),
                                                                                                  ];
                                                                                                  const loginRules = [
                                                                                                    body("email").trim().matches(emailPattern),
                                                                                                      body("password").isLength({ min: 1 }),
                                                                                                      ];

                                                                                                      // ---- JWT helpers
                                                                                                      function signToken(user) {
                                                                                                        return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
                                                                                                        }
                                                                                                        function authMiddleware(req, res, next) {
                                                                                                          const auth = req.headers.authorization || "";
                                                                                                            const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
                                                                                                              if (!token) return res.status(401).json({ error: "missing token" });
                                                                                                                try {
                                                                                                                    req.user = jwt.verify(token, JWT_SECRET);
                                                                                                                        next();
                                                                                                                          } catch {
                                                                                                                              res.status(401).json({ error: "invalid or expired token" });
                                                                                                                                }
                                                                                                                                }

                                                                                                                                // ---- API Key middleware
                                                                                                                                function requireApiKey(req, res, next) {
                                                                                                                                  const provided = req.headers["x-api-key"] || req.query.api_key || "";
                                                                                                                                    const db = readDB();
                                                                                                                                      const matchDb = db.apiKeys.find(k => k.active && k.key === provided);
                                                                                                                                        const matchEnv = GLOBAL_API_KEY && provided === GLOBAL_API_KEY;

                                                                                                                                          if (matchDb || matchEnv) return next();
                                                                                                                                            return res.status(401).json({ error: "missing or invalid api key" });
                                                                                                                                            }

                                                                                                                                            // ---- Admin guard
                                                                                                                                            function requireAdmin(req, res, next) {
                                                                                                                                              const hdr = req.headers["x-admin-secret"] || "";
                                                                                                                                                if (!ADMIN_SECRET) return res.status(500).json({ error: "ADMIN_SECRET not configured" });
                                                                                                                                                  if (hdr !== ADMIN_SECRET) return res.status(403).json({ error: "forbidden" });
                                                                                                                                                    next();
                                                                                                                                                    }

                                                                                                                                                    // ---- Health (no auth)
                                                                                                                                                    app.get("/health", (_req, res) => {
                                                                                                                                                      res.json({
                                                                                                                                                          ok: true,
                                                                                                                                                              apiBase: BASE_API_URL,
                                                                                                                                                                  hasGlobalKey: !!GLOBAL_API_KEY,
                                                                                                                                                                      dataFile: fs.existsSync(dataFile),
                                                                                                                                                                        });
                                                                                                                                                                        });

                                                                                                                                                                        // ================== ADMIN API KEYS ==================
                                                                                                                                                                        app.post("/v1/admin/api-keys", requireAdmin, (req, res) => {
                                                                                                                                                                          const name = (req.body?.name || "").trim() || "app-" + nanoid(6);
                                                                                                                                                                            const key = nanoid(32);
                                                                                                                                                                              const id = nanoid(10);

                                                                                                                                                                                const db = readDB();
                                                                                                                                                                                  const item = { id, name, key, active: true, createdAt: new Date().toISOString() };
                                                                                                                                                                                    db.apiKeys.push(item);
                                                                                                                                                                                      writeDB(db);
                                                                                                                                                                                        res.status(201).json({ id, name, key, active: true, createdAt: item.createdAt });
                                                                                                                                                                                        });

                                                                                                                                                                                        app.get("/v1/admin/api-keys", requireAdmin, (_req, res) => {
                                                                                                                                                                                          const db = readDB();
                                                                                                                                                                                            const safe = db.apiKeys.map(k => ({
                                                                                                                                                                                                id: k.id,
                                                                                                                                                                                                    name: k.name,
                                                                                                                                                                                                        keyMasked: k.key.replace(/.(?=.{4})/g, "•"),
                                                                                                                                                                                                            active: k.active,
                                                                                                                                                                                                                createdAt: k.createdAt
                                                                                                                                                                                                                  }));
                                                                                                                                                                                                                    res.json({ keys: safe, count: safe.length });
                                                                                                                                                                                                                    });

                                                                                                                                                                                                                    app.patch("/v1/admin/api-keys/:id", requireAdmin, (req, res) => {
                                                                                                                                                                                                                      const { id } = req.params;
                                                                                                                                                                                                                        const { active } = req.body || {};
                                                                                                                                                                                                                          const db = readDB();
                                                                                                                                                                                                                            const rec = db.apiKeys.find(k => k.id === id);
                                                                                                                                                                                                                              if (!rec) return res.status(404).json({ error: "not found" });
                                                                                                                                                                                                                                if (typeof active === "boolean") rec.active = active;
                                                                                                                                                                                                                                  writeDB(db);
                                                                                                                                                                                                                                    res.json({ id: rec.id, name: rec.name, active: rec.active });
                                                                                                                                                                                                                                    });

                                                                                                                                                                                                                                    app.delete("/v1/admin/api-keys/:id", requireAdmin, (req, res) => {
                                                                                                                                                                                                                                      const { id } = req.params;
                                                                                                                                                                                                                                        const db = readDB();
                                                                                                                                                                                                                                          const before = db.apiKeys.length;
                                                                                                                                                                                                                                            db.apiKeys = db.apiKeys.filter(k => k.id !== id);
                                                                                                                                                                                                                                              writeDB(db);
                                                                                                                                                                                                                                                if (db.apiKeys.length === before) return res.status(404).json({ error: "not found" });
                                                                                                                                                                                                                                                  res.json({ ok: true, deleted: id });
                                                                                                                                                                                                                                                  });

                                                                                                                                                                                                                                                  // ================== AUTH ROUTES (under /v1) ==================
                                                                                                                                                                                                                                                  const router = express.Router();
                                                                                                                                                                                                                                                  router.use("/auth", requireApiKey);

                                                                                                                                                                                                                                                  // ---- Signup
                                                                                                                                                                                                                                                  router.post("/auth/signup", async (req, res) => {
                                                                                                                                                                                                                                                    if (req.body && typeof req.body.mobile === "string") {
                                                                                                                                                                                                                                                        req.body.mobile = req.body.mobile.replace(/\D/g, "");
                                                                                                                                                                                                                                                          }
                                                                                                                                                                                                                                                            await Promise.all(signupRules.map((r) => r.run(req)));
                                                                                                                                                                                                                                                              const errors = validationResult(req);
                                                                                                                                                                                                                                                                if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

                                                                                                                                                                                                                                                                  const { name, mobile, dob, country, email, password } = req.body;
                                                                                                                                                                                                                                                                    const db = readDB();

                                                                                                                                                                                                                                                                      const exists = db.users.find((u) => u.email === email.toLowerCase() || u.mobile === mobile);
                                                                                                                                                                                                                                                                        if (exists) return res.status(409).json({ error: "User already exists" });

                                                                                                                                                                                                                                                                          const passwordHash = bcrypt.hashSync(password, 12);
                                                                                                                                                                                                                                                                            const user = {
                                                                                                                                                                                                                                                                                id: nanoid(),
                                                                                                                                                                                                                                                                                    name: name.trim(),
                                                                                                                                                                                                                                                                                        mobile,
                                                                                                                                                                                                                                                                                            dob,
                                                                                                                                                                                                                                                                                                country: country.trim(),
                                                                                                                                                                                                                                                                                                    email: email.toLowerCase(),
                                                                                                                                                                                                                                                                                                        passwordHash,
                                                                                                                                                                                                                                                                                                            createdAt: new Date().toISOString(),
                                                                                                                                                                                                                                                                                                                updatedAt: new Date().toISOString(),
                                                                                                                                                                                                                                                                                                                  };

                                                                                                                                                                                                                                                                                                                    db.users.push(user);
                                                                                                                                                                                                                                                                                                                      writeDB(db);

                                                                                                                                                                                                                                                                                                                        const token = signToken(user);
                                                                                                                                                                                                                                                                                                                          res.status(201).json({ user, token });
                                                                                                                                                                                                                                                                                                                          });

                                                                                                                                                                                                                                                                                                                          // ---- Login
                                                                                                                                                                                                                                                                                                                          router.post("/auth/login", loginRules, (req, res) => {
                                                                                                                                                                                                                                                                                                                            const errors = validationResult(req);
                                                                                                                                                                                                                                                                                                                              if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

                                                                                                                                                                                                                                                                                                                                const { email, password } = req.body;
                                                                                                                                                                                                                                                                                                                                  const db = readDB();

                                                                                                                                                                                                                                                                                                                                    const user = db.users.find((u) => u.email === email.toLowerCase());
                                                                                                                                                                                                                                                                                                                                      if (!user) return res.status(401).json({ error: "Invalid email or password" });

                                                                                                                                                                                                                                                                                                                                        const ok = bcrypt.compareSync(password, user.passwordHash);
                                                                                                                                                                                                                                                                                                                                          if (!ok) return res.status(401).json({ error: "Invalid email or password" });

                                                                                                                                                                                                                                                                                                                                            const token = signToken(user);
                                                                                                                                                                                                                                                                                                                                              res.json({ user, token });
                                                                                                                                                                                                                                                                                                                                              });

                                                                                                                                                                                                                                                                                                                                              // ---- Me
                                                                                                                                                                                                                                                                                                                                              router.get("/auth/me", authMiddleware, (req, res) => {
                                                                                                                                                                                                                                                                                                                                                const db = readDB();
                                                                                                                                                                                                                                                                                                                                                  const user = db.users.find((u) => u.id === req.user.sub);
                                                                                                                                                                                                                                                                                                                                                    if (!user) return res.status(404).json({ error: "user not found" });
                                                                                                                                                                                                                                                                                                                                                      res.json({ user });
                                                                                                                                                                                                                                                                                                                                                      });

                                                                                                                                                                                                                                                                                                                                                      // ---- Forgot Password
                                                                                                                                                                                                                                                                                                                                                      router.post("/auth/forgot", body("email").matches(emailPattern), (req, res) => {
                                                                                                                                                                                                                                                                                                                                                        const { email } = req.body;
                                                                                                                                                                                                                                                                                                                                                          const db = readDB();
                                                                                                                                                                                                                                                                                                                                                            const user = db.users.find((u) => u.email === email.toLowerCase());
                                                                                                                                                                                                                                                                                                                                                              if (!user) return res.status(404).json({ error: "User not found" });

                                                                                                                                                                                                                                                                                                                                                                const token = nanoid(24);
                                                                                                                                                                                                                                                                                                                                                                  const expires = Date.now() + 1000 * 60 * 10; // 10 min
                                                                                                                                                                                                                                                                                                                                                                    db.resetTokens.push({ token, userId: user.id, expires });
                                                                                                                                                                                                                                                                                                                                                                      writeDB(db);

                                                                                                                                                                                                                                                                                                                                                                        res.json({
                                                                                                                                                                                                                                                                                                                                                                            message: "Reset token created. Use it with /v1/auth/reset.",
                                                                                                                                                                                                                                                                                                                                                                                resetToken: token,
                                                                                                                                                                                                                                                                                                                                                                                    expiresIn: "10m",
                                                                                                                                                                                                                                                                                                                                                                                      });
                                                                                                                                                                                                                                                                                                                                                                                      });

                                                                                                                                                                                                                                                                                                                                                                                      // ---- Reset Password
                                                                                                                                                                                                                                                                                                                                                                                      router.post("/auth/reset",
                                                                                                                                                                                                                                                                                                                                                                                        [body("token").isString().isLength({ min: 10 }), body("password").isLength({ min: 8 })],
                                                                                                                                                                                                                                                                                                                                                                                          (req, res) => {
                                                                                                                                                                                                                                                                                                                                                                                              const { token, password } = req.body;
                                                                                                                                                                                                                                                                                                                                                                                                  const db = readDB();
                                                                                                                                                                                                                                                                                                                                                                                                      const reset = db.resetTokens.find((t) => t.token === token);
                                                                                                                                                                                                                                                                                                                                                                                                          if (!reset) return res.status(400).json({ error: "Invalid or expired token" });

                                                                                                                                                                                                                                                                                                                                                                                                              if (Date.now() > reset.expires) {
                                                                                                                                                                                                                                                                                                                                                                                                                    db.resetTokens = db.resetTokens.filter((t) => t.token !== token);
                                                                                                                                                                                                                                                                                                                                                                                                                          writeDB(db);
                                                                                                                                                                                                                                                                                                                                                                                                                                return res.status(400).json({ error: "Token expired" });
                                                                                                                                                                                                                                                                                                                                                                                                                                    }

                                                                                                                                                                                                                                                                                                                                                                                                                                        const user = db.users.find((u) => u.id === reset.userId);
                                                                                                                                                                                                                                                                                                                                                                                                                                            if (!user) return res.status(404).json({ error: "User not found" });

                                                                                                                                                                                                                                                                                                                                                                                                                                                user.passwordHash = bcrypt.hashSync(password, 12);
                                                                                                                                                                                                                                                                                                                                                                                                                                                    user.updatedAt = new Date().toISOString();
                                                                                                                                                                                                                                                                                                                                                                                                                                                        db.resetTokens = db.resetTokens.filter((t) => t.token !== token);
                                                                                                                                                                                                                                                                                                                                                                                                                                                            writeDB(db);

                                                                                                                                                                                                                                                                                                                                                                                                                                                                res.json({ message: "Password reset successful." });
                                                                                                                                                                                                                                                                                                                                                                                                                                                                  }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                  );

                                                                                                                                                                                                                                                                                                                                                                                                                                                                  // ---- Mount versioned API
                                                                                                                                                                                                                                                                                                                                                                                                                                                                  app.use("/v1", router);

                                                                                                                                                                                                                                                                                                                                                                                                                                                                  // ---- Start server
app.listen(PORT, HOST, () => {
    console.log(`✅ MTOS Auth API running at ${BASE_API_URL}`);
    console.log(`💾 JSON DB: ${dataFile}`);
    if (GLOBAL_API_KEY) console.log(`🔑 Global API Key enabled`);
    if (ADMIN_SECRET) console.log(`🛡  Admin endpoints active`);
});