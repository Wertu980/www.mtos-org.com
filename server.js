// server.js — MTOS Auth Backend using Neon PostgreSQL

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { nanoid } = require("nanoid");
const { Pool } = require("pg");
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

// ---- PostgreSQL Connection ----
const pool = new Pool({ connectionString: DATABASE_URL });

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

                                            // ---- Routes ----

                                            // Health check
                                            app.get("/v1/health", async (req, res) => {
                                              try {
                                                  const result = await pool.query("SELECT NOW()");
                                                      res.json({ ok: true, db_time: result.rows[0].now });
                                                        } catch (err) {
                                                            console.error(err);
                                                                res.status(500).json({ error: "DB connection failed" });
                                                                  }
                                                                  });

                                                                  // Signup
                                                                  app.post("/v1/auth/signup", requireApiKey, signupRules, async (req, res) => {
                                                                    const errors = validationResult(req);
                                                                      if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

                                                                        const { name, mobile, dob, country, email, password } = req.body;
                                                                          try {
                                                                              const existing = await pool.query("SELECT id FROM users WHERE email=$1 OR mobile=$2", [
                                                                                    email.toLowerCase(),
                                                                                          mobile,
                                                                                              ]);
                                                                                                  if (existing.rows.length > 0)
                                                                                                        return res.status(409).json({ error: "User already exists" });

                                                                                                            const passwordHash = bcrypt.hashSync(password, 12);
                                                                                                                const userId = nanoid();

                                                                                                                    await pool.query(
                                                                                                                          `INSERT INTO users (id, name, mobile, dob, country, email, password_hash)
                                                                                                                                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                                                                                                                                       [userId, name, mobile, dob, country, email.toLowerCase(), passwordHash]
                                                                                                                                           );

                                                                                                                                               const token = signToken({ id: userId, email });
                                                                                                                                                   res.status(201).json({
                                                                                                                                                         user: { id: userId, name, mobile, dob, country, email },
                                                                                                                                                               token,
                                                                                                                                                                   });
                                                                                                                                                                     } catch (err) {
                                                                                                                                                                         console.error(err);
                                                                                                                                                                             res.status(500).json({ error: "Database insert failed" });
                                                                                                                                                                               }
                                                                                                                                                                               });

                                                                                                                                                                               // Login
                                                                                                                                                                               app.post("/v1/auth/login", requireApiKey, async (req, res) => {
                                                                                                                                                                                 const { email, password } = req.body;
                                                                                                                                                                                   try {
                                                                                                                                                                                       const result = await pool.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
                                                                                                                                                                                           if (result.rows.length === 0)
                                                                                                                                                                                                 return res.status(401).json({ error: "Invalid email or password" });

                                                                                                                                                                                                     const user = result.rows[0];
                                                                                                                                                                                                         const ok = bcrypt.compareSync(password, user.password_hash);
                                                                                                                                                                                                             if (!ok) return res.status(401).json({ error: "Invalid email or password" });

                                                                                                                                                                                                                 const token = signToken(user);
                                                                                                                                                                                                                     res.json({
                                                                                                                                                                                                                           user: {
                                                                                                                                                                                                                                   id: user.id,
                                                                                                                                                                                                                                           name: user.name,
                                                                                                                                                                                                                                                   mobile: user.mobile,
                                                                                                                                                                                                                                                           dob: user.dob,
                                                                                                                                                                                                                                                                   country: user.country,
                                                                                                                                                                                                                                                                           email: user.email,
                                                                                                                                                                                                                                                                                 },
                                                                                                                                                                                                                                                                                       token,
                                                                                                                                                                                                                                                                                           });
                                                                                                                                                                                                                                                                                             } catch (err) {
                                                                                                                                                                                                                                                                                                 console.error(err);
                                                                                                                                                                                                                                                                                                     res.status(500).json({ error: "Database query failed" });
                                                                                                                                                                                                                                                                                                       }
                                                                                                                                                                                                                                                                                                       });

                                                                                                                                                                                                                                                                                                       // Me
                                                                                                                                                                                                                                                                                                       app.get("/v1/auth/me", requireApiKey, authMiddleware, async (req, res) => {
                                                                                                                                                                                                                                                                                                         try {
                                                                                                                                                                                                                                                                                                             const result = await pool.query(
                                                                                                                                                                                                                                                                                                                   "SELECT id, name, mobile, dob, country, email FROM users WHERE id=$1",
                                                                                                                                                                                                                                                                                                                         [req.user.sub]
                                                                                                                                                                                                                                                                                                                             );
                                                                                                                                                                                                                                                                                                                                 if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
                                                                                                                                                                                                                                                                                                                                     res.json({ user: result.rows[0] });
                                                                                                                                                                                                                                                                                                                                       } catch (err) {
                                                                                                                                                                                                                                                                                                                                           console.error(err);
                                                                                                                                                                                                                                                                                                                                               res.status(500).json({ error: "Database read failed" });
                                                                                                                                                                                                                                                                                                                                                 }
                                                                                                                                                                                                                                                                                                                                                 });

                                                                                                                                                                                                                                                                                                                                                 // Start Server
                                                                                                                                                                                                                                                                                                                                                 app.listen(PORT, HOST, () => {
                                                                                                                                                                                                                                                                                                                                                   console.log(`✅ MTOS Auth Server connected to Neon DB`);
                                                                                                                                                                                                                                                                                                                                                     console.log(`🌐 API: https://www-mtos-org-com.onrender.com/v1`);
                                                                                                                                                                                                                                                                                                                                                     });