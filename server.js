require("dotenv").config();
const express = require("express");
const { OpenAI } = require("openai");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");

// ===== STARTUP VALIDATION =====
const REQUIRED_ENV = ["JWT_SECRET", "OPENAI_API_KEY", "MJ_APIKEY_PUBLIC", "MJ_APIKEY_PRIVATE", "MJ_SENDER_EMAIL"];
REQUIRED_ENV.forEach((key) => {
  if (!process.env[key]) {
    console.error(`❌ Thiếu biến môi trường: ${key}`);
    process.exit(1);
  }
});
if (process.env.JWT_SECRET.length < 32) {
  console.error("❌ JWT_SECRET quá ngắn (cần ≥32 ký tự)");
  process.exit(1);
}

const app = express();
const server = http.createServer(app);

// ===== CORS CONFIG =====
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim())
  : ["*"];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS blocked: " + origin));
    }
  },
  credentials: true,
};

const io = new Server(server, {
  cors: corsOptions,
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ["polling", "websocket"],
  allowUpgrades: true,
  path: "/socket.io/",
});
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ===== DATABASE =====
if (!fs.existsSync("data")) fs.mkdirSync("data", { recursive: true });
const db = new Database("data/saas.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("synchronous = NORMAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS bots (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    system_prompt TEXT NOT NULL,
    primary_color TEXT DEFAULT '#2563eb',
    bot_avatar TEXT DEFAULT '🤖',
    welcome_message TEXT DEFAULT 'Xin chào! Tôi có thể giúp gì cho bạn?',
    position TEXT DEFAULT 'right',
    allowed_domains TEXT DEFAULT '*',
    model TEXT DEFAULT 'gpt-4o-mini',
    max_tokens INTEGER DEFAULT 500,
    is_active INTEGER DEFAULT 1,
    business_info TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS chat_sessions (
    id TEXT PRIMARY KEY,
    bot_id TEXT NOT NULL,
    visitor_id TEXT,
    operator_mode INTEGER DEFAULT 0,
    operator_id TEXT DEFAULT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(bot_id) REFERENCES bots(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user','assistant','operator','system')),
    content TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS session_contacts (
    session_id TEXT PRIMARY KEY,
    name TEXT,
    phone TEXT,
    email TEXT,
    updated_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    bot_id TEXT NOT NULL,
    name TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    nodes TEXT DEFAULT '[]',
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(bot_id) REFERENCES bots(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS failed_logins (
    ip TEXT NOT NULL,
    email TEXT NOT NULL,
    attempted_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_bots_user ON bots(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_bot ON chat_sessions(bot_id);
  CREATE INDEX IF NOT EXISTS idx_messages_session ON chat_messages(session_id);
  CREATE INDEX IF NOT EXISTS idx_contacts_session ON session_contacts(session_id);
  CREATE INDEX IF NOT EXISTS idx_reset_tokens_hash ON password_reset_tokens(token_hash);
`);

// ===== MIGRATIONS =====
const migrations = [
  `ALTER TABLE bots ADD COLUMN business_info TEXT DEFAULT ''`,
  `ALTER TABLE chat_sessions ADD COLUMN operator_mode INTEGER DEFAULT 0`,
  `ALTER TABLE chat_sessions ADD COLUMN operator_id TEXT DEFAULT NULL`,
];
migrations.forEach((sql) => { try { db.exec(sql); } catch (e) {} });

// ===== LIVE AGENT STATE =====
const agentSessions = new Map();

// ===== INPUT SANITIZE =====
function sanitize(str, maxLen = 1000) {
  if (typeof str !== "string") return "";
  return str.trim().slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function isValidUUID(id) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}

// ===== MAILJET =====
async function sendEmail({ to, toName, subject, htmlContent, textContent }) {
  const payload = {
    Messages: [
      {
        From: {
          Email: process.env.MJ_SENDER_EMAIL,
          Name: process.env.MJ_SENDER_NAME || "AI Chat SaaS",
        },
        To: [{ Email: to, Name: toName || to }],
        Subject: subject,
        TextPart: textContent || "",
        HTMLPart: htmlContent || "",
      },
    ],
  };

  const credentials = Buffer.from(
    `${process.env.MJ_APIKEY_PUBLIC}:${process.env.MJ_APIKEY_PRIVATE}`
  ).toString("base64");

  const response = await fetch("https://api.mailjet.com/v3.1/send", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${credentials}`,
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json();
  if (!response.ok || data.Messages?.[0]?.Status !== "success") {
    console.error("[Mailjet Error]", JSON.stringify(data));
    throw new Error("Gửi email thất bại");
  }
  return data;
}

function buildResetEmailHtml(resetUrl, email) {
  return `
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Đặt lại mật khẩu</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="max-width:560px;margin:40px auto;padding:0 16px">
    <div style="background:#fff;border-radius:16px;overflow:hidden;border:1px solid #e2e8f0">
      <div style="background:linear-gradient(135deg,#1e40af,#2563eb);padding:32px;text-align:center">
        <div style="font-size:40px;margin-bottom:8px">🔐</div>
        <h1 style="color:#fff;margin:0;font-size:22px;font-weight:700">Đặt lại mật khẩu</h1>
        <p style="color:#bfdbfe;margin:8px 0 0;font-size:14px">AI Chat SaaS</p>
      </div>
      <div style="padding:32px">
        <p style="color:#374151;font-size:15px;margin:0 0 16px">Xin chào,</p>
        <p style="color:#374151;font-size:15px;margin:0 0 24px;line-height:1.6">
          Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản 
          <strong>${email}</strong>. Nhấn nút bên dưới để tạo mật khẩu mới.
        </p>
        <div style="text-align:center;margin-bottom:24px">
          <a href="${resetUrl}" 
             style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;
                    padding:14px 32px;border-radius:10px;font-size:15px;font-weight:600;
                    letter-spacing:0.3px">
            Đặt lại mật khẩu →
          </a>
        </div>
        <div style="background:#f8fafc;border-radius:10px;padding:16px;margin-bottom:24px">
          <p style="margin:0;font-size:13px;color:#64748b;line-height:1.6">
            ⏰ Link này sẽ hết hạn sau <strong>30 phút</strong>.<br/>
            🛡️ Nếu bạn không yêu cầu đặt lại, vui lòng bỏ qua email này.
          </p>
        </div>
        <p style="color:#94a3b8;font-size:12px;margin:0;word-break:break-all">
          Hoặc copy link: <a href="${resetUrl}" style="color:#2563eb">${resetUrl}</a>
        </p>
      </div>
      <div style="background:#f8fafc;padding:16px 32px;border-top:1px solid #e2e8f0;text-align:center">
        <p style="margin:0;font-size:12px;color:#94a3b8">
          © ${new Date().getFullYear()} AI Chat SaaS — Email tự động, vui lòng không reply.
        </p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

// ===== CONTACT HELPERS =====
function extractAndSaveContact(sessionId, message) {
  const existing = db.prepare("SELECT * FROM session_contacts WHERE session_id = ?").get(sessionId) || {};
  const raw = message.trim();

  const emailMatch = raw.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i);
  const email = emailMatch ? emailMatch[0].toLowerCase() : existing.email || null;

  const rawNoEmail = raw.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, "");
  const normalized = rawNoEmail.replace(/[.\-()]/g, " ").replace(/\s+/g, " ");

  let phone = existing.phone || null;
  const phonePatterns = [
    /\+\d{1,3}\s?\d{3}\s?\d{3}\s?\d{4}/,
    /0\d{2}\s?\d{3}\s?\d{4}/,
    /0\d{3}\s?\d{3}\s?\d{3}/,
    /\d{3}\s\d{3}\s\d{4}/,
    /\d{3}-\d{3}-\d{4}/,
    /\b\d{10}\b/,
    /\b\d{9}\b/,
  ];
  for (const p of phonePatterns) {
    const m = normalized.match(p);
    if (m) { phone = m[0].trim(); break; }
  }

  let name = existing.name || null;
  const vnPatterns = [
    /(?:tên\s+(?:tôi|mình|em|anh|chị)\s+là|(?:tôi|mình|em|anh|chị)\s+tên\s+là)\s+([^\d,;.!?\n]{2,40})/i,
    /(?:tôi\s+là|mình\s+là|em\s+là|anh\s+là|chị\s+là)\s+([^\d,;.!?\n]{2,40})/i,
  ];
  for (const p of vnPatterns) {
    const m = raw.match(p);
    if (m) { name = m[1].trim().replace(/[,;.!?].*$/, "").trim(); break; }
  }
  if (!name) {
    const enPatterns = [
      /(?:my\s+name\s+is|i(?:'m| am)|this\s+is|call\s+me)\s+([A-Za-z][a-zA-Z\s]{1,30})/i,
      /(?:name|tên)\s*[:：]\s*([A-Za-zÀ-ỹ][a-zA-Zà-ỹÀ-Ỹ\s]{1,30})/i,
    ];
    for (const p of enPatterns) {
      const m = raw.match(p);
      if (m) { name = m[1].trim().replace(/[,;.!?\d].*$/, "").trim(); break; }
    }
  }
  if (!name) {
    const parts = raw.split(/[,;\n\r]+/).map((p) => p.trim()).filter(Boolean);
    for (const part of parts) {
      if (/\d{5,}/.test(part)) continue;
      if (/@/.test(part)) continue;
      if (/https?:/i.test(part)) continue;
      if (/số|phone|tel|sdt|zalo|hotline/i.test(part)) continue;
      if (/^[A-Za-zÀ-ỹà-ỹ][A-Za-zÀ-ỹà-ỹ\s.'-]{1,39}$/.test(part)) {
        const wordCount = part.trim().split(/\s+/).length;
        if (wordCount >= 1 && wordCount <= 5) { name = part.trim(); break; }
      }
    }
  }
  if (name) {
    name = name.replace(/[\d,;!?.]+$/, "").trim();
    if (name.length < 2) name = existing.name || null;
  }

  console.log(`[Contact] session=${sessionId} name="${name}" phone="${phone}" email="${email}"`);

  db.prepare(`
    INSERT INTO session_contacts (session_id, name, phone, email)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      name  = COALESCE(excluded.name,  name),
      phone = COALESCE(excluded.phone, phone),
      email = COALESCE(excluded.email, email),
      updated_at = strftime('%s','now')
  `).run(sessionId, name, phone, email);

  return { name, phone, email };
}

function buildContactPrompt(sessionId) {
  const c = db.prepare("SELECT * FROM session_contacts WHERE session_id = ?").get(sessionId);
  const missing = [];
  if (!c?.name) missing.push("tên");
  if (!c?.phone) missing.push("số điện thoại");
  if (!c?.email) missing.push("email");
  if (missing.length === 0) return "";
  return `\n\n━━━ THU THẬP THÔNG TIN KHÁCH ━━━\nThông tin chưa có: ${missing.join(", ")}\nNếu cuộc trò chuyện đang diễn ra tự nhiên, hãy khéo léo xin ${missing[0]} của khách. KHÔNG hỏi ngay nếu khách chỉ hỏi câu thông thường.`;
}

// ===== FLOW ENGINE =====
function checkFlowTrigger(message, botId) {
  const flows = db.prepare("SELECT * FROM flows WHERE bot_id = ? AND is_active = 1").all(botId);
  for (const flow of flows) {
    const nodes = JSON.parse(flow.nodes || "[]");
    const trigger = nodes.find((n) => n.type === "trigger");
    if (!trigger?.config?.keywords) continue;
    const keywords = trigger.config.keywords.split(",").map((k) => k.trim().toLowerCase()).filter(Boolean);
    if (keywords.some((k) => message.toLowerCase().includes(k))) {
      return { matched: true, nodes };
    }
  }
  return { matched: false };
}

// ===== MIDDLEWARE =====
app.use(cors(corsOptions));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// ===== SERVE WIDGET.JS =====
app.get("/static/widget.js", (req, res) => {
  const filePath = path.join(__dirname, "public", "widget.js");
  try {
    const content = fs.readFileSync(filePath, "utf8");
    res.setHeader("Content-Type", "application/javascript");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(content);
  } catch (err) {
    console.error("widget.js error:", err.message);
    res.status(404).send("// widget not found");
  }
});

app.use("/static", express.static(path.join(__dirname, "public"), {
  setHeaders: (res, fp) => {
    if (fp.endsWith(".js")) res.setHeader("Content-Type", "application/javascript");
  },
}));

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  hsts: process.env.NODE_ENV === "production" ? { maxAge: 31536000, includeSubDomains: true } : false,
}));

// ===== RATE LIMITERS =====
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Quá nhiều lần thử, vui lòng đợi 15 phút" },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 giờ
  max: 3,
  message: { error: "Quá nhiều yêu cầu đặt lại mật khẩu, vui lòng đợi 1 giờ" },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.body?.email || req.ip,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => (req.body?.botId || "unknown") + "_" + req.ip,
  message: { error: "Quá nhiều tin nhắn, vui lòng đợi." },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
});
app.use("/api/", apiLimiter);

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Token không hợp lệ hoặc đã hết hạn" });
  }
}

// ===== AUTH ROUTES =====
app.post("/api/auth/register", authLimiter, async (req, res) => {
  const email    = sanitize(req.body.email || "", 254).toLowerCase();
  const password = sanitize(req.body.password || "", 128);

  // Chi tiết validation
  const errors = {};
  if (!email) errors.email = "Email là bắt buộc";
  else if (!isValidEmail(email)) errors.email = "Định dạng email không hợp lệ";

  if (!password) errors.password = "Mật khẩu là bắt buộc";
  else if (password.length < 8) errors.password = "Mật khẩu phải có ít nhất 8 ký tự";
  else if (!/[A-Z]/.test(password) && !/[0-9]/.test(password))
    errors.password = "Mật khẩu nên chứa chữ hoa hoặc số để bảo mật hơn";

  if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

  if (db.prepare("SELECT id FROM users WHERE email = ?").get(email))
    return res.status(409).json({ errors: { email: "Email này đã được đăng ký" } });

  const hashed = await bcrypt.hash(password, 12);
  const id = uuidv4();
  db.prepare("INSERT INTO users (id, email, password) VALUES (?, ?, ?)").run(id, email, hashed);
  const token = jwt.sign({ id, email }, process.env.JWT_SECRET, { expiresIn: "30d" });
  res.status(201).json({ token, user: { id, email } });
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const email    = sanitize(req.body.email || "", 254).toLowerCase();
  const password = sanitize(req.body.password || "", 128);

  const errors = {};
  if (!email) errors.email = "Email là bắt buộc";
  else if (!isValidEmail(email)) errors.email = "Định dạng email không hợp lệ";
  if (!password) errors.password = "Mật khẩu là bắt buộc";

  if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  // Timing-safe
  const dummyHash = "$2a$12$dummyhashfordummycompare000000000000000000000000000000";
  const valid = user ? await bcrypt.compare(password, user.password)
                     : await bcrypt.compare(password, dummyHash).then(() => false);

  if (!valid) {
    db.prepare("INSERT INTO failed_logins (ip, email) VALUES (?, ?)").run(req.ip, email);
    return res.status(401).json({ errors: { password: "Email hoặc mật khẩu không đúng" } });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, email: user.email } });
});

// ===== FORGOT PASSWORD =====
app.post("/api/auth/forgot-password", resetLimiter, async (req, res) => {
  const email = sanitize(req.body.email || "", 254).toLowerCase();

  if (!email) return res.status(400).json({ errors: { email: "Email là bắt buộc" } });
  if (!isValidEmail(email)) return res.status(400).json({ errors: { email: "Định dạng email không hợp lệ" } });

  // Luôn trả 200 để tránh user enumeration
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) {
    return res.json({ message: "Nếu email tồn tại, chúng tôi đã gửi hướng dẫn đặt lại mật khẩu." });
  }

  // Xoá token cũ chưa dùng
  db.prepare("DELETE FROM password_reset_tokens WHERE user_id = ? AND used = 0").run(user.id);

  // Tạo token ngẫu nhiên
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const expiresAt = Math.floor(Date.now() / 1000) + 30 * 60; // 30 phút

  db.prepare(`
    INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(uuidv4(), user.id, tokenHash, expiresAt);

  const appUrl = (process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, "");
  const resetUrl = `${appUrl}/reset-password?token=${rawToken}`;

  try {
    await sendEmail({
      to: email,
      toName: email.split("@")[0],
      subject: "🔐 Đặt lại mật khẩu — AI Chat SaaS",
      htmlContent: buildResetEmailHtml(resetUrl, email),
      textContent: `Đặt lại mật khẩu của bạn tại: ${resetUrl}\nLink hết hạn sau 30 phút.`,
    });
    console.log(`[Reset] Đã gửi email đặt lại mật khẩu cho ${email}`);
  } catch (err) {
    console.error("[Reset Email Error]", err.message);
    // Xoá token nếu gửi mail thất bại
    db.prepare("DELETE FROM password_reset_tokens WHERE token_hash = ?").run(tokenHash);
    return res.status(500).json({ error: "Không thể gửi email. Vui lòng thử lại sau." });
  }

  res.json({ message: "Nếu email tồn tại, chúng tôi đã gửi hướng dẫn đặt lại mật khẩu." });
});

// ===== RESET PASSWORD =====
app.post("/api/auth/reset-password", authLimiter, async (req, res) => {
  const rawToken       = sanitize(req.body.token || "", 200);
  const newPassword    = sanitize(req.body.password || "", 128);
  const confirmPassword = sanitize(req.body.confirmPassword || "", 128);

  const errors = {};
  if (!rawToken) errors.token = "Token không hợp lệ";
  if (!newPassword) errors.password = "Mật khẩu mới là bắt buộc";
  else if (newPassword.length < 8) errors.password = "Mật khẩu phải có ít nhất 8 ký tự";
  if (!confirmPassword) errors.confirmPassword = "Vui lòng xác nhận mật khẩu";
  else if (newPassword !== confirmPassword) errors.confirmPassword = "Mật khẩu xác nhận không khớp";

  if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const now = Math.floor(Date.now() / 1000);

  const record = db.prepare(`
    SELECT * FROM password_reset_tokens
    WHERE token_hash = ? AND used = 0 AND expires_at > ?
  `).get(tokenHash, now);

  if (!record) {
    return res.status(400).json({ errors: { token: "Link đặt lại mật khẩu không hợp lệ hoặc đã hết hạn" } });
  }

  const hashed = await bcrypt.hash(newPassword, 12);
  db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashed, record.user_id);
  db.prepare("UPDATE password_reset_tokens SET used = 1 WHERE id = ?").run(record.id);

  console.log(`[Reset] Đặt lại mật khẩu thành công cho user=${record.user_id}`);
  res.json({ message: "Đặt lại mật khẩu thành công! Bạn có thể đăng nhập ngay." });
});

// ===== VERIFY RESET TOKEN (để frontend kiểm tra trước khi render form) =====
app.get("/api/auth/verify-reset-token", (req, res) => {
  const rawToken = sanitize(req.query.token || "", 200);
  if (!rawToken) return res.status(400).json({ valid: false, error: "Token trống" });

  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const now = Math.floor(Date.now() / 1000);

  const record = db.prepare(`
    SELECT id, expires_at FROM password_reset_tokens
    WHERE token_hash = ? AND used = 0 AND expires_at > ?
  `).get(tokenHash, now);

  if (!record) return res.json({ valid: false, error: "Token không hợp lệ hoặc đã hết hạn" });
  
  const remainingMinutes = Math.ceil((record.expires_at - now) / 60);
  res.json({ valid: true, expiresInMinutes: remainingMinutes });
});

// ===== CHANGE PASSWORD (for logged-in users) =====
app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  const currentPassword = sanitize(req.body.currentPassword || "", 128);
  const newPassword     = sanitize(req.body.newPassword || "", 128);
  const confirmPassword = sanitize(req.body.confirmPassword || "", 128);

  const errors = {};
  if (!currentPassword) errors.currentPassword = "Mật khẩu hiện tại là bắt buộc";
  if (!newPassword) errors.newPassword = "Mật khẩu mới là bắt buộc";
  else if (newPassword.length < 8) errors.newPassword = "Mật khẩu phải có ít nhất 8 ký tự";
  if (!confirmPassword) errors.confirmPassword = "Vui lòng xác nhận mật khẩu";
  else if (newPassword !== confirmPassword) errors.confirmPassword = "Mật khẩu xác nhận không khớp";

  if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  const valid = await bcrypt.compare(currentPassword, user.password);
  if (!valid) return res.status(401).json({ errors: { currentPassword: "Mật khẩu hiện tại không đúng" } });

  const hashed = await bcrypt.hash(newPassword, 12);
  db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashed, req.user.id);
  res.json({ message: "Đổi mật khẩu thành công!" });
});

// ===== BOT ROUTES =====
app.get("/api/bots", authMiddleware, (req, res) => {
  res.json(db.prepare("SELECT * FROM bots WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id));
});

app.post("/api/bots", authMiddleware, (req, res) => {
  const name          = sanitize(req.body.name || "", 100);
  const system_prompt = sanitize(req.body.system_prompt || "", 4000);
  const business_info = sanitize(req.body.business_info || "", 3000);

  const errors = {};
  if (!name) errors.name = "Tên bot là bắt buộc";
  if (!system_prompt) errors.system_prompt = "System prompt là bắt buộc";
  if (Object.keys(errors).length > 0) return res.status(400).json({ errors });

  const botCount = db.prepare("SELECT COUNT(*) as c FROM bots WHERE user_id = ?").get(req.user.id);
  if (botCount.c >= 20)
    return res.status(429).json({ error: "Tối đa 20 bot mỗi tài khoản" });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO bots (id, user_id, name, system_prompt, primary_color, bot_avatar,
      welcome_message, position, allowed_domains, model, max_tokens, business_info)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, req.user.id, name, system_prompt,
    sanitize(req.body.primary_color || "#2563eb", 20),
    sanitize(req.body.bot_avatar || "🤖", 10),
    sanitize(req.body.welcome_message || "Xin chào! Tôi có thể giúp gì cho bạn?", 500),
    ["right", "left"].includes(req.body.position) ? req.body.position : "right",
    sanitize(req.body.allowed_domains || "*", 500),
    ["gpt-4o-mini", "gpt-4o"].includes(req.body.model) ? req.body.model : "gpt-4o-mini",
    Math.min(Math.max(parseInt(req.body.max_tokens) || 500, 100), 2000),
    business_info
  );
  res.status(201).json(db.prepare("SELECT * FROM bots WHERE id = ?").get(id));
});

app.put("/api/bots/:id", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.id))
    return res.status(400).json({ error: "ID không hợp lệ" });

  const bot = db.prepare("SELECT * FROM bots WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!bot) return res.status(404).json({ error: "Bot không tồn tại" });

  const allowed = ["name","system_prompt","primary_color","bot_avatar","welcome_message",
                   "position","allowed_domains","model","max_tokens","is_active","business_info"];
  const updates = allowed.filter((f) => req.body[f] !== undefined);
  if (!updates.length) return res.status(400).json({ error: "Không có dữ liệu cập nhật" });

  const values = updates.map((f) => {
    if (f === "model") return ["gpt-4o-mini","gpt-4o"].includes(req.body[f]) ? req.body[f] : bot.model;
    if (f === "position") return ["right","left"].includes(req.body[f]) ? req.body[f] : bot.position;
    if (f === "max_tokens") return Math.min(Math.max(parseInt(req.body[f]) || 500, 100), 2000);
    if (f === "is_active") return req.body[f] ? 1 : 0;
    return sanitize(String(req.body[f]), 4000);
  });

  db.prepare(`UPDATE bots SET ${updates.map((f) => `${f} = ?`).join(", ")} WHERE id = ?`).run(...values, req.params.id);
  res.json(db.prepare("SELECT * FROM bots WHERE id = ?").get(req.params.id));
});

app.delete("/api/bots/:id", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.id))
    return res.status(400).json({ error: "ID không hợp lệ" });
  db.prepare("DELETE FROM bots WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ===== EMBED SCRIPT =====
app.get("/api/bots/:id/script", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.id))
    return res.status(400).json({ error: "ID không hợp lệ" });
  const bot = db.prepare("SELECT * FROM bots WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!bot) return res.status(404).json({ error: "Bot không tồn tại" });
  const appUrl = (process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, "");
  res.json({
    script: `<!-- AI Chat Widget -->\n<script>\n  window.AIChatConfig = { botId: "${bot.id}", serverUrl: "${appUrl}" };\n  (function(d){var s=d.createElement('script');s.src='${appUrl}/static/widget.js';s.async=true;d.head.appendChild(s);})(document);\n<\/script>`,
    botId: bot.id,
  });
});

// ===== WIDGET BOT INFO =====
app.get("/api/widget/bot/:botId", (req, res) => {
  if (!isValidUUID(req.params.botId))
    return res.status(400).json({ error: "ID không hợp lệ" });
  const bot = db.prepare(
    "SELECT id, name, primary_color, bot_avatar, welcome_message, position, is_active FROM bots WHERE id = ?"
  ).get(req.params.botId);
  if (!bot || !bot.is_active) return res.status(404).json({ error: "Bot không hoạt động" });
  res.json(bot);
});

// ===== CHAT API =====
app.post("/api/widget/chat", chatLimiter, async (req, res) => {
  const message   = sanitize(req.body.message || "", 1000);
  const botId     = sanitize(req.body.botId || "", 50);
  const sessionId = sanitize(req.body.sessionId || "", 50);

  if (!message || !botId)
    return res.status(400).json({ error: "Dữ liệu không hợp lệ" });
  if (botId && !isValidUUID(botId))
    return res.status(400).json({ error: "botId không hợp lệ" });
  if (sessionId && !isValidUUID(sessionId))
    return res.status(400).json({ error: "sessionId không hợp lệ" });

  const bot = db.prepare("SELECT * FROM bots WHERE id = ? AND is_active = 1").get(botId);
  if (!bot) return res.status(404).json({ error: "Bot không tồn tại" });

  let sid = sessionId || null;
  if (!sid) {
    sid = uuidv4();
    db.prepare("INSERT INTO chat_sessions (id, bot_id) VALUES (?, ?)").run(sid, botId);
  } else {
    const sess = db.prepare("SELECT id FROM chat_sessions WHERE id = ? AND bot_id = ?").get(sid, botId);
    if (!sess) {
      sid = uuidv4();
      db.prepare("INSERT INTO chat_sessions (id, bot_id) VALUES (?, ?)").run(sid, botId);
    }
  }

  db.prepare("INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)").run(sid, "user", message);
  const contactUpdate = extractAndSaveContact(sid, message);

  io.to(`bot:${botId}`).emit("contact:updated", { sessionId: sid, contact: contactUpdate });
  io.to(`bot:${botId}`).emit("message:new", { role: "user", content: message, sessionId: sid, botId, contact: contactUpdate });

  const session = db.prepare("SELECT * FROM chat_sessions WHERE id = ?").get(sid);
  if (session?.operator_mode) {
    return res.json({ reply: null, sessionId: sid, operatorMode: true });
  }

  const flowMatch = checkFlowTrigger(message, botId);
  if (flowMatch.matched) {
    const msgNode = flowMatch.nodes.find((n) => n.type === "send_message");
    if (msgNode?.config?.message) {
      const reply = sanitize(msgNode.config.message, 2000);
      db.prepare("INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)").run(sid, "assistant", reply);
      io.to(`bot:${botId}`).emit("message:new", { role: "assistant", content: reply, sessionId: sid, botId });
      return res.json({ reply, sessionId: sid, flowTriggered: true });
    }
  }

  const history = db.prepare(
    `SELECT role, content FROM chat_messages
     WHERE session_id = ? AND role IN ('user','assistant','operator')
     ORDER BY created_at DESC LIMIT 10`
  ).all(sid).reverse().map((m) => ({
    role: m.role === "operator" ? "assistant" : m.role,
    content: m.content,
  }));

  const businessBlock = bot.business_info?.trim()
    ? `\n\n━━━ THÔNG TIN DOANH NGHIỆP ━━━\n${bot.business_info.trim()}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n- Giải đáp rõ về dịch vụ/sản phẩm rồi tự nhiên mời liên hệ\n- Cung cấp hotline/địa chỉ khi phù hợp\n- KHÔNG spam thông tin liên hệ`
    : "";

  const fullSystemPrompt = bot.system_prompt + businessBlock + buildContactPrompt(sid);

  try {
    const response = await openai.chat.completions.create({
      model: bot.model,
      max_tokens: bot.max_tokens,
      temperature: 0.7,
      messages: [
        { role: "system", content: fullSystemPrompt },
        ...history,
        { role: "user", content: message },
      ],
    });
    const reply = response.choices[0].message.content;
    db.prepare("INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)").run(sid, "assistant", reply);
    io.to(`bot:${botId}`).emit("message:new", { role: "assistant", content: reply, sessionId: sid, botId });
    res.json({ reply, sessionId: sid });
  } catch (err) {
    console.error("[OpenAI Error]", err.message);
    res.status(500).json({ error: "Lỗi xử lý, vui lòng thử lại." });
  }
});

// ===== CONVERSATIONS + CONTACTS =====
app.get("/api/bots/:botId/conversations", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.botId)) return res.status(400).json({ error: "ID không hợp lệ" });
  const bot = db.prepare("SELECT id FROM bots WHERE id = ? AND user_id = ?").get(req.params.botId, req.user.id);
  if (!bot) return res.status(403).json({ error: "Không có quyền" });
  const sessions = db.prepare(`
    SELECT s.id, s.created_at, s.operator_mode,
      (SELECT content FROM chat_messages WHERE session_id = s.id ORDER BY created_at ASC LIMIT 1) as first_message,
      (SELECT COUNT(*) FROM chat_messages WHERE session_id = s.id) as message_count,
      c.name as contact_name, c.phone as contact_phone, c.email as contact_email
    FROM chat_sessions s
    LEFT JOIN session_contacts c ON c.session_id = s.id
    WHERE s.bot_id = ? ORDER BY s.created_at DESC LIMIT 50
  `).all(req.params.botId);
  res.json(sessions);
});

app.get("/api/sessions/:sessionId/messages", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.sessionId)) return res.status(400).json({ error: "ID không hợp lệ" });
  const session = db.prepare(`
    SELECT s.id FROM chat_sessions s
    JOIN bots b ON b.id = s.bot_id
    WHERE s.id = ? AND b.user_id = ?
  `).get(req.params.sessionId, req.user.id);
  if (!session) return res.status(403).json({ error: "Không có quyền" });
  res.json(db.prepare("SELECT * FROM chat_messages WHERE session_id = ? ORDER BY created_at ASC").all(req.params.sessionId));
});

app.get("/api/sessions/:sessionId/contact", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.sessionId)) return res.status(400).json({ error: "ID không hợp lệ" });
  const session = db.prepare(`
    SELECT s.id FROM chat_sessions s
    JOIN bots b ON b.id = s.bot_id
    WHERE s.id = ? AND b.user_id = ?
  `).get(req.params.sessionId, req.user.id);
  if (!session) return res.status(403).json({ error: "Không có quyền" });
  res.json(db.prepare("SELECT * FROM session_contacts WHERE session_id = ?").get(req.params.sessionId) || {});
});

// ===== FLOW ROUTES =====
app.get("/api/bots/:botId/flows", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.botId)) return res.status(400).json({ error: "ID không hợp lệ" });
  const bot = db.prepare("SELECT id FROM bots WHERE id = ? AND user_id = ?").get(req.params.botId, req.user.id);
  if (!bot) return res.status(403).json({ error: "Không có quyền" });
  const flows = db.prepare("SELECT * FROM flows WHERE bot_id = ? ORDER BY created_at DESC").all(req.params.botId);
  res.json(flows.map((f) => ({ ...f, nodes: JSON.parse(f.nodes || "[]") })));
});

app.post("/api/bots/:botId/flows", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.botId)) return res.status(400).json({ error: "ID không hợp lệ" });
  const bot = db.prepare("SELECT id FROM bots WHERE id = ? AND user_id = ?").get(req.params.botId, req.user.id);
  if (!bot) return res.status(403).json({ error: "Không có quyền" });
  const name = sanitize(req.body.name || "", 100);
  if (!name) return res.status(400).json({ error: "Tên flow là bắt buộc" });
  const id = uuidv4();
  db.prepare("INSERT INTO flows (id, bot_id, name, nodes) VALUES (?, ?, ?, ?)").run(
    id, req.params.botId, name, JSON.stringify(req.body.nodes || [])
  );
  const flow = db.prepare("SELECT * FROM flows WHERE id = ?").get(id);
  res.status(201).json({ ...flow, nodes: JSON.parse(flow.nodes) });
});

app.put("/api/flows/:id", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.id)) return res.status(400).json({ error: "ID không hợp lệ" });
  const flow = db.prepare(`
    SELECT f.id FROM flows f
    JOIN bots b ON b.id = f.bot_id
    WHERE f.id = ? AND b.user_id = ?
  `).get(req.params.id, req.user.id);
  if (!flow) return res.status(403).json({ error: "Không có quyền" });

  const fields = []; const vals = [];
  if (req.body.name      !== undefined) { fields.push("name = ?");      vals.push(sanitize(req.body.name, 100)); }
  if (req.body.nodes     !== undefined) { fields.push("nodes = ?");     vals.push(JSON.stringify(req.body.nodes)); }
  if (req.body.is_active !== undefined) { fields.push("is_active = ?"); vals.push(req.body.is_active ? 1 : 0); }
  if (!fields.length) return res.status(400).json({ error: "Không có dữ liệu" });

  db.prepare(`UPDATE flows SET ${fields.join(", ")} WHERE id = ?`).run(...vals, req.params.id);
  const updated = db.prepare("SELECT * FROM flows WHERE id = ?").get(req.params.id);
  res.json({ ...updated, nodes: JSON.parse(updated.nodes) });
});

app.delete("/api/flows/:id", authMiddleware, (req, res) => {
  if (!isValidUUID(req.params.id)) return res.status(400).json({ error: "ID không hợp lệ" });
  const flow = db.prepare(`
    SELECT f.id FROM flows f
    JOIN bots b ON b.id = f.bot_id
    WHERE f.id = ? AND b.user_id = ?
  `).get(req.params.id, req.user.id);
  if (!flow) return res.status(403).json({ error: "Không có quyền" });
  db.prepare("DELETE FROM flows WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

// ===== SOCKET.IO - LIVE AGENT =====
io.on("connection", (socket) => {
  socket.on("operator:join", ({ token, botId }) => {
    try {
      if (!isValidUUID(botId)) return socket.emit("error", { message: "botId không hợp lệ" });
      const user = jwt.verify(token, process.env.JWT_SECRET);
      const bot = db.prepare("SELECT id FROM bots WHERE id = ? AND user_id = ?").get(botId, user.id);
      if (!bot) return socket.emit("error", { message: "Không có quyền truy cập bot này" });

      socket.userId = user.id;
      socket.botId  = botId;
      socket.join(`operator:${user.id}`);
      socket.join(`bot:${botId}`);

      const sessions = db.prepare(`
        SELECT s.id, s.created_at, s.operator_mode,
          (SELECT content FROM chat_messages WHERE session_id = s.id ORDER BY created_at DESC LIMIT 1) as last_message,
          (SELECT COUNT(*) FROM chat_messages WHERE session_id = s.id) as msg_count,
          c.name as contact_name, c.phone as contact_phone, c.email as contact_email
        FROM chat_sessions s
        LEFT JOIN session_contacts c ON c.session_id = s.id
        WHERE s.bot_id = ? ORDER BY s.created_at DESC LIMIT 30
      `).all(botId);
      socket.emit("sessions:list", sessions);
    } catch (e) {
      socket.emit("error", { message: "Auth failed" });
    }
  });

  socket.on("operator:takeover", ({ sessionId }) => {
    if (!socket.userId || !isValidUUID(sessionId)) return;
    db.prepare("UPDATE chat_sessions SET operator_mode = 1, operator_id = ? WHERE id = ?").run(socket.id, sessionId);
    agentSessions.set(sessionId, socket.id);
    socket.join(`session:${sessionId}`);
    const messages = db.prepare("SELECT * FROM chat_messages WHERE session_id = ? ORDER BY created_at ASC").all(sessionId);
    const contact  = db.prepare("SELECT * FROM session_contacts WHERE session_id = ?").get(sessionId);
    socket.emit("session:history", { sessionId, messages, contact });
    io.to(`session:${sessionId}`).emit("agent:joined", { message: "✅ Nhân viên hỗ trợ đã tham gia. Chúng tôi sẽ phản hồi ngay!" });
  });

  socket.on("operator:message", ({ sessionId, message }) => {
    if (!socket.userId || !sessionId || !message?.trim()) return;
    if (!isValidUUID(sessionId)) return;
    const msg = sanitize(message, 2000);
    db.prepare("INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)").run(sessionId, "operator", msg);
    socket.to(`session:${sessionId}`).emit("message:new", { role: "operator", content: msg, sessionId });
    socket.emit("message:new", { role: "operator", content: msg, sessionId });
  });

  socket.on("operator:release", ({ sessionId }) => {
    if (!socket.userId || !isValidUUID(sessionId)) return;
    db.prepare("UPDATE chat_sessions SET operator_mode = 0, operator_id = NULL WHERE id = ?").run(sessionId);
    agentSessions.delete(sessionId);
    socket.leave(`session:${sessionId}`);
    io.to(`session:${sessionId}`).emit("agent:left", { message: "🤖 Nhân viên đã rời khỏi. Bot AI tiếp tục hỗ trợ!" });
  });

  socket.on("widget:join", ({ sessionId }) => {
    if (!sessionId || !isValidUUID(sessionId)) return;
    socket.join(`session:${sessionId}`);
    socket.sessionId = sessionId;
  });

  socket.on("session:view", ({ sessionId }) => {
    if (!socket.userId || !isValidUUID(sessionId)) return;
    const messages = db.prepare("SELECT * FROM chat_messages WHERE session_id = ? ORDER BY created_at ASC").all(sessionId);
    const contact  = db.prepare("SELECT * FROM session_contacts WHERE session_id = ?").get(sessionId);
    socket.emit("session:history", { sessionId, messages, contact });
  });

  socket.on("disconnect", () => {
    if (socket.userId) {
      agentSessions.forEach((operatorSocketId, sessionId) => {
        if (operatorSocketId === socket.id) {
          db.prepare("UPDATE chat_sessions SET operator_mode = 0, operator_id = NULL WHERE id = ?").run(sessionId);
          agentSessions.delete(sessionId);
          io.to(`session:${sessionId}`).emit("agent:left", { message: "🤖 Nhân viên đã ngắt kết nối. Bot AI tiếp tục hỗ trợ!" });
        }
      });
    }
  });
});

// ===== PREVIEW PAGE =====
app.get("/preview/:botId", (req, res) => {
  if (!isValidUUID(req.params.botId))
    return res.status(400).send("Bot ID không hợp lệ");
  const botId  = req.params.botId;
  const appUrl = (process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, "");
  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Preview Widget</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;min-height:100vh}
    .preview-bar{background:#1e293b;color:#fff;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;font-size:13px;position:fixed;top:0;left:0;right:0;z-index:9999999}
    .preview-dot{width:10px;height:10px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
    .preview-label{font-weight:600;font-size:14px}
    .preview-sub{color:#94a3b8;font-size:12px;margin-top:2px}
    .preview-close{background:#334155;color:#fff;border:none;border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer;text-decoration:none;display:inline-block}
    .fake-site{margin-top:52px;padding:40px 24px;max-width:900px;margin:52px auto 0}
    .fake-hero{background:#fff;border-radius:16px;padding:48px 40px;margin-bottom:24px;border:1px solid #e2e8f0;text-align:center}
    .fake-hero h1{font-size:32px;font-weight:800;color:#0f172a;margin-bottom:12px}
    .fake-hero p{color:#64748b;font-size:16px;line-height:1.6;max-width:500px;margin:0 auto 24px}
    .fake-btn{background:#2563eb;color:#fff;border:none;border-radius:8px;padding:12px 28px;font-size:15px;font-weight:600;cursor:default}
    .fake-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:24px}
    .fake-card{background:#fff;border-radius:12px;padding:24px;border:1px solid #e2e8f0}
    .preview-hint{position:fixed;top:70px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;padding:10px 20px;border-radius:20px;font-size:13px;font-weight:500;pointer-events:none;animation:fadeout 4s forwards;z-index:9999998}
    @keyframes fadeout{0%,60%{opacity:1}100%{opacity:0}}
  </style>
</head>
<body>
  <div class="preview-bar">
    <div style="display:flex;align-items:center;gap:10px">
      <div class="preview-dot"></div>
      <div><div class="preview-label">🔍 Preview Widget</div><div class="preview-sub">Bot ID: ${botId}</div></div>
    </div>
    <a href="/" class="preview-close">← Về Dashboard</a>
  </div>
  <div class="preview-hint">👇 Chat widget đang chạy ở góc màn hình — hãy thử chat!</div>
  <div class="fake-site">
    <div class="fake-hero">
      <h1>Website của bạn</h1>
      <p>Trang demo giả lập — kiểm tra widget trước khi gắn lên website thật.</p>
      <button class="fake-btn">Khám phá sản phẩm</button>
    </div>
    <div class="fake-cards">
      <div class="fake-card"><div style="font-size:28px;margin-bottom:12px">🚀</div><h3 style="font-size:15px;font-weight:600;margin-bottom:6px">Sản phẩm A</h3><p style="font-size:13px;color:#64748b">Mô tả ngắn về sản phẩm.</p></div>
      <div class="fake-card"><div style="font-size:28px;margin-bottom:12px">💡</div><h3 style="font-size:15px;font-weight:600;margin-bottom:6px">Sản phẩm B</h3><p style="font-size:13px;color:#64748b">Mô tả ngắn về sản phẩm.</p></div>
      <div class="fake-card"><div style="font-size:28px;margin-bottom:12px">🎯</div><h3 style="font-size:15px;font-weight:600;margin-bottom:6px">Sản phẩm C</h3><p style="font-size:13px;color:#64748b">Mô tả ngắn về sản phẩm.</p></div>
    </div>
  </div>
  <script>
    window.AIChatConfig = { botId: "${botId}", serverUrl: "${appUrl}" };
    (function(d){var s=d.createElement('script');s.src='${appUrl}/static/widget.js';s.async=true;d.head.appendChild(s);})(document);
  <\/script>
</body>
</html>`);
});

// ===== RESET PASSWORD PAGE =====
app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard/index.html"));
});

// ===== DEPLOY WEBHOOK =====
const { execSync } = require("child_process");
app.post("/deploy", (req, res) => {
  const key = req.query.key;
  if (key !== process.env.DEPLOY_KEY) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  try {
    const output = execSync("cd ~/www/chatapp.theoceanwide.com && git pull && npm install && pm2 restart chatapp --update-env",
      { encoding: "utf8" }
    );
    console.log("[Deploy]", output);
    res.json({ success: true, output });
  } catch (err) {
    console.error("[Deploy Error]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ===== SERVE DASHBOARD =====
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "dashboard/index.html")));

// ===== GLOBAL ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  const isProd = process.env.NODE_ENV === "production";
  res.status(err.status || 500).json({ error: isProd ? "Lỗi server" : err.message });
});

app.use((req, res) => res.status(404).json({ error: "Endpoint không tồn tại" }));

// ===== GRACEFUL SHUTDOWN =====
process.on("SIGTERM", () => {
  console.log("[Server] SIGTERM — đóng server...");
  server.close(() => { db.close(); process.exit(0); });
});
process.on("SIGINT", () => {
  console.log("[Server] SIGINT — đóng server...");
  server.close(() => { db.close(); process.exit(0); });
});

// ===== START =====
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Server: http://localhost:${PORT} [${process.env.NODE_ENV || "development"}]`));