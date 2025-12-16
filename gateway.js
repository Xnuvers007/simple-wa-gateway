const makeWASocket = require('@whiskeysockets/baileys').default;
const { useMultiFileAuthState, fetchLatestBaileysVersion, DisconnectReason } = require('@whiskeysockets/baileys');
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bcrypt = require('bcryptjs');
const qrcode = require('qrcode');
const pino = require('pino');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const os = require('os');
const chalk = require('chalk');
const https = require('https');

dotenv.config({
  path: path.join(__dirname, '.env')
})

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const app = express();
const PORT = process.env.GATEWAY_PORT || 3001;
const API_PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.API_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Queue & throttle config
const GAP_MS = Number(process.env.SEND_GAP_MS || 250);
const MAX_PER_REQ = Number(process.env.MAX_PER_REQ || 1500);
const sendQueue = [];
let queueRunning = false;

// Session configuration
app.use(session({
  store: new FileStore({ path: './sessions', logFn: function(){} }),
  secret: process.env.SESSION_SECRET || 'whatsapp-gateway-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'gateway-views'));
app.use(express.static(path.join(__dirname, 'gateway-public')));

// Admin credentials file
const CREDS_FILE = path.join(__dirname, 'admin-creds.json');

// Initialize admin credentials
function initAdminCredentials() {
  const envUsername = process.env.ADMIN_USERNAME || 'indra';
  const envPassword = process.env.ADMIN_PASSWORD || 'indra';

  // Cek apakah file admin-creds.json ada
  if (fs.existsSync(CREDS_FILE)) {
    try {
      const existingCreds = JSON.parse(fs.readFileSync(CREDS_FILE, 'utf-8'));

      // Cek apakah username di .env berbeda dengan yang ada di file
      // Atau jika password di .env tidak match dengan hash yang ada
      const usernameChanged = existingCreds.username !== envUsername;
      const passwordValid = existingCreds.password && bcrypt.compareSync(envPassword, existingCreds.password);

      if (usernameChanged || !passwordValid) {
        console.log(chalk.yellow('⚠️  Perubahan terdeteksi di .env, membuat ulang admin-creds.json...'));

        // Hapus file lama
        fs.unlinkSync(CREDS_FILE);

        // Buat file baru dengan credential dari .env
        const newPassword = bcrypt.hashSync(envPassword, 10);
        fs.writeFileSync(CREDS_FILE, JSON.stringify({
          username: envUsername,
          password: newPassword
        }, null, 2));

        console.log(chalk.green(`✅ Admin credentials diperbarui (username: ${envUsername})`));
      } else {
        console.log(chalk.gray('ℹ️  Admin credentials sudah sesuai dengan .env'));
      }
    } catch (error) {
      console.error(chalk.red('❌ Error membaca admin-creds.json, membuat ulang...'));
      fs.unlinkSync(CREDS_FILE);

      // Buat file baru
      const newPassword = bcrypt.hashSync(envPassword, 10);
      fs.writeFileSync(CREDS_FILE, JSON.stringify({
        username: envUsername,
        password: newPassword
      }, null, 2));

      console.log(chalk.green(`✅ Admin credentials dibuat (username: ${envUsername})`));
    }
  } else {
    // File tidak ada, buat baru
    const newPassword = bcrypt.hashSync(envPassword, 10);
    fs.writeFileSync(CREDS_FILE, JSON.stringify({
      username: envUsername,
      password: newPassword
    }, null, 2));

    console.log(chalk.green(`✅ Admin credentials dibuat (username: ${envUsername})`));
  }
}

// Get admin credentials
function getAdminCredentials() {
  if (fs.existsSync(CREDS_FILE)) return JSON.parse(fs.readFileSync(CREDS_FILE, 'utf-8'));
  return null;
}

// Update admin password
function updateAdminPassword(newPassword) {
  const envUsername = process.env.ADMIN_USERNAME || 'indra';
  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  fs.writeFileSync(CREDS_FILE, JSON.stringify({
    username: envUsername,
    password: hashedPassword
  }, null, 2));
  console.log(chalk.green(`✅ Password admin berhasil diperbarui`));
}

// Global bot state
let sock = null;
let qrData = null;
let phoneNumber = null;
let isConnected = false;
let connectionStatus = 'disconnected';

// Helper functions
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function normalizePhoneTo62(raw) {
  if (!raw) return null;
  let p = String(raw).trim().replace(/[^\d+]/g, '');
  if (p.startsWith('+')) p = p.slice(1);
  if (p.startsWith('0')) p = '62' + p.slice(1);
  if (!/^62\d{8,13}$/.test(p)) return null;
  return p;
}

function toJid(raw) {
  const n = normalizePhoneTo62(raw);
  return n ? `${n}@s.whatsapp.net` : null;
}

function sanitizeText(input, maxLen = 5000) {
  if (typeof input !== 'string') return '';
  let s = input.replace(/\r/g, '').trim();
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}

// Queue worker
async function runQueue() {
  if (queueRunning) return;
  queueRunning = true;
  try {
    while (sendQueue.length) {
      const task = sendQueue.shift();
      try {
        const r = await sock.sendMessage(task.jid, { text: task.text });
        task.resolve({ ok: true, messageId: r?.key?.id || null });
      } catch (e) {
        task.resolve({ ok: false, error: e?.message || String(e) });
      }
      await sleep(GAP_MS);
    }
  } finally {
    queueRunning = false;
  }
}

function enqueueSend(jid, text) {
  return new Promise((resolve) => {
    sendQueue.push({ jid, text, resolve });
    runQueue();
  });
}

// Auth middleware
/*function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  res.redirect('/');
}*/
// Auth middleware (Versi Diperbaiki)
function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) {
    return next();
  }

  if (req.path === '/status' || req.headers.accept?.includes('json')) {
    return res.status(401).json({ error: 'session_expired' });
  }

  res.redirect('/');
}

// API Key middleware
function requireApiKey(req, res, next) {
  const key = req.header('X-API-Key') || req.query.key;
  if (!API_KEY || key !== API_KEY) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  return next();
}

morgan.token('statusColor', (req, res) => {
  const status = res.statusCode;
  if (status >= 500) {
    return chalk.red(status);       // error server
  } else if (status >= 400) {
    return chalk.yellow(status);    // client error
  } else if (status >= 300) {
    return chalk.cyan(status);      // redirect
  } else if (status >= 200) {
    return chalk.green(status);     // sukses
  }
  return chalk.white(status);       // default
});

const customFormat = (tokens, req, res) => {
  return [
    chalk.gray(tokens.method(req, res)),
    tokens.url(req, res),
    tokens['statusColor'](req, res),
    chalk.magenta(tokens['response-time'](req, res) + ' ms')
  ].join(' ');
};

// Initialize WhatsApp Bot (QR only)
async function initWhatsAppBot(phone) {
  try {
    // Jika ada phone number yang diberikan, set phoneNumber
    // Jika null (auto-load), akan diset dari state.creds.me nanti
    if (phone) phoneNumber = phone;

    qrData = null;
    connectionStatus = 'connecting';

    const sessionPath = path.join(__dirname, process.env.SESSION || 'gateway_session');

    // Pastikan folder session ada
    if (!fs.existsSync(sessionPath)) {
      fs.mkdirSync(sessionPath, { recursive: true });
    }

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const { version } = await fetchLatestBaileysVersion();

    // Jika auto-load (phone = null) dan ada session, ambil nomor dari state
    if (!phone && state.creds?.me?.id) {
      phoneNumber = state.creds.me.id.split(':')[0];
      console.log(chalk.green(`📱 Memuat nomor dari sesi: ${phoneNumber}`));
    }

    sock = makeWASocket({
      version,
      logger,
      auth: state,
      printQRInTerminal: false, // QR hanya untuk web
      syncFullHistory: false,
      browser: ['WhatsApp Gateway SIGAP', 'Chrome', '10.0.0']
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
      if (qr) {
        qrData = await qrcode.toDataURL(qr);
        console.log('📱 QR Code generated');
      }

      if (connection === 'open') {
        isConnected = true;
        connectionStatus = 'connected';
        console.log('✅ Terhubung ke WhatsApp');
        if (qrData) {
            console.log(chalk.yellow('🔄 Login baru terdeteksi via QR!'));
            console.log(chalk.yellow('🔄 Me-restart sistem untuk memuat sesi baru...'));

            // Tunggu 2 detik agar sesi tersimpan sempurna, lalu matikan proses
            setTimeout(() => {
                process.exit(0);
                // process.exit(0) akan mematikan aplikasi.
                // Karena Anda pakai PM2, PM2 akan otomatis menyalakannya lagi (Auto Restart).
            }, 2000);
        }
        // --- AKHIR TAMBAHAN ---

        // Reset QR Data agar tidak restart terus menerus
        qrData = null;
      } else if (connection === 'close') {
        isConnected = false;
        connectionStatus = 'disconnected';
        const isLoggedOut = lastDisconnect?.error?.output?.statusCode === DisconnectReason.loggedOut;
        if (isLoggedOut) {
          sock = null;
          console.log('🚪 Logged out');
        } else {
          console.log('🔁 Reconnecting...');
          connectionStatus = 'reconnecting';
          setTimeout(() => initWhatsAppBot(phone), 3000);
        }
      } else if (connection === 'connecting') {
        connectionStatus = 'connecting';
      }
    });

      sock.ev.on('call', async (calls) => {
        for (const c of calls) {
        if (c.status === 'offer') {
            const participant = c.participants?.[0]?.tag || c.from;
            try {
            await sock.rejectCall(c.id, c.from, participant);
            // const phone = (participant || c.from).split('@')[0];
            // await sock.sendMessage(c.from, { text: `Panggilan dari https://wa.me/${phone} ditolak otomatis.` });
            await sock.sendMessage(c.from, { text: `Nomor ini tidak dapat di telepon` });
            } catch (err) {
            console.error('Gagal menolak panggilan:', err);
            }
        }
        }
    });

    sock.ev.on('messages.upsert', ({ messages }) => {
      const m = messages?.[0];
      if (!m?.message || m.key.fromMe) return;
      const text =
        m.message?.conversation ||
        m.message?.extendedTextMessage?.text ||
        m.message?.imageMessage?.caption ||
        m.message?.videoMessage?.caption || '';

      if (text?.toLowerCase() === 'ping') {
        sock.sendMessage(m.key.remoteJid, { text: '🏓 Pong! WhatsApp Gateway is active.' });
      }
      if (text?.toLowerCase() === 'status') {
        const statusMsg = `📡 Status Gateway:\n\n` +
                          `- Nomor: ${phoneNumber || 'Tidak terhubung'}\n` +
                          `- Koneksi: ${isConnected ? 'Terhubung' : 'Tidak terhubung'}\n` +
                          `- Status: ${connectionStatus}`;
        sock.sendMessage(m.key.remoteJid, { text: statusMsg });
      }
    });

    return { ok: true, qrData };
  } catch (error) {
    console.error('Error initializing bot:', error);
    connectionStatus = 'error';
    return { ok: false, error: error.message };
  }
}

// Stop bot and clear session
async function stopBot() {
  try { if (sock) await sock.logout(); } catch (e) { console.log('Logout error:', e); }

  sock = null;
  isConnected = false;
  connectionStatus = 'disconnected';
  phoneNumber = null;
  qrData = null;

  const sessionPath = path.join(__dirname, process.env.SESSION || 'gateway_session');
  if (fs.existsSync(sessionPath)) fs.rmSync(sessionPath, { recursive: true, force: true });
}

// Routes
app.get('/', (req, res) => {
  if (req.session && req.session.loggedIn) return res.redirect('/dashboard');
  res.render('login', {
    error: null,
    turnstileSiteKey: process.env.CLOUDFLARE_TURNSTILE_SITE_KEY || null
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const turnstileResponse = req.body['cf-turnstile-response'];
  const turnstileSiteKey = process.env.CLOUDFLARE_TURNSTILE_SITE_KEY;
  const turnstileSecretKey = process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY;

  // Validasi Cloudflare Turnstile jika diaktifkan
  if (turnstileSiteKey && turnstileSecretKey) {
    if (!turnstileResponse) {
      return res.render('login', {
        error: 'Captcha tidak valid. Silakan coba lagi.',
        turnstileSiteKey
      });
    }

    try {
      // Verify Cloudflare Turnstile menggunakan https module
      const verifyData = JSON.stringify({
        secret: turnstileSecretKey,
        response: turnstileResponse,
        remoteip: req.ip || req.connection.remoteAddress
      });

      const verifyResult = await new Promise((resolve, reject) => {
        const options = {
          hostname: 'challenges.cloudflare.com',
          port: 443,
          path: '/turnstile/v0/siteverify',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': verifyData.length
          }
        };

        const request = https.request(options, (response) => {
          let data = '';
          response.on('data', (chunk) => { data += chunk; });
          response.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(new Error('Invalid JSON response'));
            }
          });
        });

        request.on('error', reject);
        request.write(verifyData);
        request.end();
      });

      if (!verifyResult.success) {
        console.log(chalk.yellow('⚠️  Cloudflare Turnstile verification failed:'), verifyResult);
        return res.render('login', {
          error: 'Verifikasi captcha gagal. Silakan coba lagi.',
          turnstileSiteKey
        });
      }

      console.log(chalk.green('✅ Cloudflare Turnstile verified successfully'));
    } catch (error) {
      console.error(chalk.red('❌ Error verifying Cloudflare Turnstile:'), error.message);
      return res.render('login', {
        error: 'Terjadi kesalahan saat verifikasi captcha.',
        turnstileSiteKey
      });
    }
  }

  const admin = getAdminCredentials();

  if (!admin) return res.render('login', {
    error: 'Admin credentials not found',
    turnstileSiteKey
  });

  if (username === admin.username && bcrypt.compareSync(password, admin.password)) {
    req.session.loggedIn = true;
    req.session.username = username;
    return res.redirect('/dashboard');
  }

  res.render('login', {
    error: 'Username atau password salah',
    turnstileSiteKey
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', {
    username: req.session.username,
    phoneNumber,
    qrData,
    isConnected,
    connectionStatus
  });
});

app.post('/connect', requireAuth, async (req, res) => {
  const { phone } = req.body;
  if (!phone || !/^62\d{8,13}$/.test(phone)) return res.json({ ok: false, error: 'Format nomor tidak valid. Gunakan format 628xxxxx' });
  if (phoneNumber && isConnected) return res.json({ ok: false, error: 'Sudah ada nomor yang terhubung. Hapus nomor terlebih dahulu.' });

  const result = await initWhatsAppBot(phone);
  res.json(result);
});

app.post('/disconnect', requireAuth, async (req, res) => {
  await stopBot();
  res.json({ ok: true });
});

app.get('/status', requireAuth, (req, res) => {
  res.json({ ok: true, phoneNumber, qrData, isConnected, connectionStatus });
});

app.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const admin = getAdminCredentials();

  if (!bcrypt.compareSync(currentPassword, admin.password)) return res.json({ ok: false, error: 'Password lama salah' });
  if (newPassword.length < 4) return res.json({ ok: false, error: 'Password minimal 4 karakter' });

  updateAdminPassword(newPassword);
  res.json({ ok: true, message: 'Password berhasil diubah' });
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/'); });

// ============================================================
// API Endpoints (WhatsApp Gateway)
// ============================================================
const apiApp = express();

apiApp.disable('x-powered-by');
apiApp.use(helmet());
apiApp.use(express.json({ limit: '10mb' }));
apiApp.use(express.urlencoded({ extended: false, limit: '10mb' }));
apiApp.use(morgan('tiny'));
apiApp.use(morgan(customFormat));

// CORS configuration
const scheme = process.env.NODE_ENV === 'production' ? 'https' : 'http';
const lanIps = [];
const nets = os.networkInterfaces();
for (const name in nets) {
  for (const iface of nets[name] || []) {
    if (iface && iface.family === 'IPv4' && !iface.internal) {
      lanIps.push(iface.address);
    }
  }
}

const allowedOrigins = [
  `http://localhost:${API_PORT}`,
  ...lanIps.map(addr => `${scheme}://${addr}:${API_PORT}`)
];

apiApp.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-API-Key']
}));

// Health check (no auth required)
apiApp.get('/health', (req, res) => {
  res.type('text/plain').send(`ok=${true}; ready=${isConnected}`);
});

// Status check (no auth required)
apiApp.get('/status', (req, res) => {
  res.json({
    ok: true,
    ready: isConnected,
    phoneNumber: phoneNumber || null
  });
});

// Apply API key middleware to all routes below
apiApp.use(requireApiKey);

// GET /pesan - Send single message via query params
apiApp.get('/pesan', async (req, res) => {
  try {
    if (!isConnected) return res.status(503).json({ ok: false, error: 'wa_not_ready' });

    const jid = toJid(req.query.wa);
    const pesan = sanitizeText(req.query.pesan);
    if (!jid || !pesan) return res.status(400).json({ ok: false, error: 'invalid_input' });

    const result = await enqueueSend(jid, pesan);
    return res.json({
      ok: result.ok,
      to: req.query.wa,
      messageId: result.messageId || null,
      error: result.error || null
    });
  } catch {
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// POST /pesan - Send message(s) via JSON body
apiApp.post('/pesan', async (req, res) => {
  try {
    if (!isConnected) return res.status(503).json({ ok: false, error: 'wa_not_ready' });

    const text = sanitizeText(req.body.pesan);
    let list = req.body.wa;
    if (!list || !text) return res.status(400).json({ ok: false, error: 'invalid_input' });

    list = Array.isArray(list) ? list : [list];
    if (list.length > MAX_PER_REQ) {
      return res.status(413).json({ ok: false, error: 'too_many_recipients' });
    }

    const results = [];
    for (const num of list) {
      const jid = toJid(num);
      if (!jid) {
        results.push({ to: num, ok: false, error: 'invalid_wa' });
        continue;
      }
      const r = await enqueueSend(jid, text);
      results.push({
        to: num,
        ok: r.ok,
        messageId: r.messageId || null,
        error: r.error || null
      });
    }

    return res.json({ ok: true, queued: results.length, results });
  } catch {
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Auto-load existing session on startup
async function autoLoadSession() {
  try {
    const sessionPath = path.join(__dirname, process.env.SESSION || 'gateway_session');
    const credsPath = path.join(sessionPath, 'creds.json');

    // Cek apakah ada session yang tersimpan
    if (fs.existsSync(credsPath)) {
      const creds = JSON.parse(fs.readFileSync(credsPath, 'utf-8'));

      // Cek apakah sudah pernah login (ada data me/user)
      if (creds.me && creds.me.id) {
        console.log(chalk.cyan('🔄 Ditemukan sesi tersimpan, memuat otomatis...'));
        console.log(chalk.gray(`   User: ${creds.me.id}`));

        // Load session tanpa parameter phone karena sudah ada
        await initWhatsAppBot(null);
      } else {
        console.log(chalk.yellow('⚠️  Sesi ditemukan tapi belum lengkap. Silakan connect via dashboard.'));
      }
    } else {
      console.log(chalk.gray('ℹ️  Tidak ada sesi tersimpan. Silakan connect via dashboard.'));
    }
  } catch (error) {
    console.error(chalk.red('❌ Error saat memuat sesi:'), error.message);
  }
}

// Initialize and start servers
initAdminCredentials();

app.listen(PORT, () => {
  console.log('============================================================');
  console.log('WhatsApp Gateway - QR Only Version');
  console.log('============================================================');
  console.log(`🌐 Dashboard: http://localhost:${PORT}`);
  console.log(`   Login: username=${ADMIN_USERNAME || 'NOT SET'}, password=${ADMIN_PASSWORD || 'NOT SET'}`);
  console.log('============================================================');

  // Auto-load session setelah server siap
  autoLoadSession();
});

apiApp.listen(API_PORT, () => {
  console.log('============================================================');
  console.log('WhatsApp API Gateway');
  console.log('============================================================');
  console.log(`🌐 API Server: http://localhost:${API_PORT}`);
  lanIps.forEach(ipAddr => {
    console.log(`   LAN IP: ${scheme}://${ipAddr}:${API_PORT}`);
  });
  console.log(`🔑 API Key: ${API_KEY || 'NOT SET'}`);
  console.log('============================================================');
  console.log('Endpoints:');
  console.log('  GET  /health - Health check');
  console.log('  GET  /status - Connection status');
  console.log('  GET  /pesan?wa=628xxx&pesan=hello&key=YOUR_KEY');
  console.log('  POST /pesan - JSON body: { wa: "628xxx", pesan: "hello" }');
  console.log('============================================================');
});

process.on('SIGINT', async () => {
  console.log('\n⚠️  Shutting down gracefully...');
  if (sock) await sock.ws.close();
  process.exit(0);
});
