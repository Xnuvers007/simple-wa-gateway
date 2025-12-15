const makeWASocket = require('@whiskeysockets/baileys').default;
const {
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason
} = require('@whiskeysockets/baileys');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const qrcode = require('qrcode');
const pino = require('pino');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

dotenv.config();

const logger = pino({ level: 'info' });
const app = express();
const PORT = process.env.GATEWAY_PORT || 3001;

// Session configuration
app.use(session({
  secret: 'whatsapp-gateway-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true
  }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'gateway-views'));
app.use(express.static(path.join(__dirname, 'gateway-public')));

// User credentials file
const CREDS_FILE = path.join(__dirname, 'admin-creds.json');

// Initialize admin credentials
function initAdminCredentials() {
  if (!fs.existsSync(CREDS_FILE)) {
    const defaultPassword = bcrypt.hashSync('indra', 10);
    fs.writeFileSync(CREDS_FILE, JSON.stringify({
      username: 'indra',
      password: defaultPassword
    }, null, 2));
    console.log('✅ Admin credentials created (username: indra, password: indra)');
  }
}

// Get admin credentials
function getAdminCredentials() {
  if (fs.existsSync(CREDS_FILE)) {
    return JSON.parse(fs.readFileSync(CREDS_FILE, 'utf-8'));
  }
  return null;
}

// Update admin password
function updateAdminPassword(newPassword) {
  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  fs.writeFileSync(CREDS_FILE, JSON.stringify({
    username: 'indra',
    password: hashedPassword
  }, null, 2));
}

// Global bot state
let sock = null;
let qrData = null;
let pairingCode = null;
let phoneNumber = null;
let isConnected = false;
let connectionStatus = 'disconnected';

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) {
    return next();
  }
  res.redirect('/');
}

// Initialize WhatsApp Bot
async function initWhatsAppBot(phone, useQR = false) {
  try {
    phoneNumber = phone;
    qrData = null;
    pairingCode = null;
    connectionStatus = 'connecting';

    const sessionPath = path.join(__dirname, 'gateway_session');
    if (!fs.existsSync(sessionPath)) {
      fs.mkdirSync(sessionPath, { recursive: true });
    }

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const { version } = await fetchLatestBaileysVersion();

    sock = makeWASocket({
      version,
      logger,
      auth: state,
      printQRInTerminal: false,
      syncFullHistory: false
    });

    sock.ev.on('creds.update', saveCreds);

    // Connection update handler
    sock.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
      if (connection === 'open') {
        isConnected = true;
        connectionStatus = 'connected';
        console.log('✅ Terhubung ke WhatsApp');
      } else if (connection === 'close') {
        isConnected = false;
        connectionStatus = 'disconnected';
        const isLoggedOut = lastDisconnect?.error?.output?.statusCode === DisconnectReason.loggedOut;
        const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.connectionClosed;
        
        if (isLoggedOut) {
          console.log('🚪 Logged out');
          sock = null;
        } else if (shouldReconnect) {
          console.log('🔁 Reconnecting...');
          connectionStatus = 'reconnecting';
          setTimeout(() => initWhatsAppBot(phone, useQR), 30000);
        }
      } else if (connection === 'connecting') {
        connectionStatus = 'connecting';
      }

      // Generate QR code
      if (qr && useQR) {
        qrData = await qrcode.toDataURL(qr);
        console.log('📱 QR Code generated');
      }
    });

    // Request pairing code AFTER connection is ready (for new devices only)
    if (!useQR && !state.creds?.registered) {
      // Wait for connection to be ready
      setTimeout(async () => {
        if (sock && connectionStatus === 'connecting') {
          try {
            const code = await sock.requestPairingCode(phone);
            pairingCode = code;
            console.log(`📲 Pairing code untuk ${phone}: ${code}`);
          } catch (e) {
            console.error('Gagal generate pairing code:', e);
          }
        }
      }, 30000);
    }

    sock.ev.on('messages.upsert', ({ messages }) => {
      const m = messages?.[0];
      if (!m?.message || m.key.fromMe) return;
      const text =
        m.message?.conversation ||
        m.message?.extendedTextMessage?.text ||
        m.message?.imageMessage?.caption ||
        m.message?.videoMessage?.caption || '';
      
      if (text) {
        console.log(`📩 Pesan dari ${m.key.remoteJid}: ${text}`);
        
        if (text.toLowerCase() === 'ping') {
          sock.sendMessage(m.key.remoteJid, { 
            text: '🏓 Pong! WhatsApp Gateway is active.' 
          });
        }
      }
    });

    return { ok: true, pairingCode, qrData };
  } catch (error) {
    console.error('Error initializing bot:', error);
    connectionStatus = 'error';
    return { ok: false, error: error.message };
  }
}

// Stop bot and clear session
async function stopBot() {
  try {
    if (sock) {
      await sock.logout();
    }
  } catch (e) {
    console.log('Logout error:', e);
  }
  
  sock = null;
  isConnected = false;
  connectionStatus = 'disconnected';
  phoneNumber = null;
  qrData = null;
  pairingCode = null;

  // Delete session folder
  const sessionPath = path.join(__dirname, 'gateway_session');
  if (fs.existsSync(sessionPath)) {
    fs.rmSync(sessionPath, { recursive: true, force: true });
  }
}

// Routes
app.get('/', (req, res) => {
  if (req.session && req.session.loggedIn) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const admin = getAdminCredentials();

  if (!admin) {
    return res.render('login', { error: 'Admin credentials not found' });
  }

  if (username === admin.username && bcrypt.compareSync(password, admin.password)) {
    req.session.loggedIn = true;
    req.session.username = username;
    return res.redirect('/dashboard');
  }

  res.render('login', { error: 'Username atau password salah' });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', {
    username: req.session.username,
    phoneNumber,
    pairingCode,
    qrData,
    isConnected,
    connectionStatus
  });
});

app.post('/connect', requireAuth, async (req, res) => {
  const { phone, method } = req.body;

  if (!phone || !/^62\d{8,13}$/.test(phone)) {
    return res.json({ ok: false, error: 'Format nomor tidak valid. Gunakan format 628xxxxx' });
  }

  // Only allow one connection
  if (phoneNumber && isConnected) {
    return res.json({ ok: false, error: 'Sudah ada nomor yang terhubung. Hapus nomor terlebih dahulu.' });
  }

  const useQR = method === 'qr';
  const result = await initWhatsAppBot(phone, useQR);
  
  res.json(result);
});

app.post('/disconnect', requireAuth, async (req, res) => {
  await stopBot();
  res.json({ ok: true });
});

app.get('/status', requireAuth, (req, res) => {
  res.json({
    ok: true,
    phoneNumber,
    pairingCode,
    qrData,
    isConnected,
    connectionStatus
  });
});

app.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const admin = getAdminCredentials();

  if (!bcrypt.compareSync(currentPassword, admin.password)) {
    return res.json({ ok: false, error: 'Password lama salah' });
  }

  if (newPassword.length < 4) {
    return res.json({ ok: false, error: 'Password minimal 4 karakter' });
  }

  updateAdminPassword(newPassword);
  res.json({ ok: true, message: 'Password berhasil diubah' });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Initialize and start server
initAdminCredentials();

app.listen(PORT, () => {
  console.log('============================================================');
  console.log('WhatsApp Gateway - Simple Version');
  console.log('============================================================');
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log('   Login: username=indra, password=indra');
  console.log('============================================================');
});
