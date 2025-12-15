# WhatsApp Gateway API Documentation

## Overview
WhatsApp Gateway dengan dual server:
- **Dashboard Server**: Port 3001 (Web UI untuk manajemen bot)
- **API Server**: Port 3000 (REST API untuk kirim pesan)

## Konfigurasi (.env)
```env
SESSION=auth
LOG_LEVEL=info
PORT=3000                # API Server port
GATEWAY_PORT=3001        # Dashboard port
NODE_ENV=development

API_KEY=xxxxx            # API Key untuk autentikasi
SESSION_SECRET=xxxx

SEND_GAP_MS=250          # Jeda antar pesan (ms)
MAX_PER_REQ=1500         # Maksimal nomor per request
```

## Dashboard (Port 3001)
### Login
- URL: `http://localhost:3001`
- Username: `indra`
- Password: `indra`

### Fitur Dashboard:
1. **Login dengan bcrypt authentication**
2. **Generate QR Code** untuk koneksi WhatsApp
3. **Monitor status koneksi** real-time
4. **Hapus nomor** (logout & clear session)
5. **Ganti password** admin

## API Endpoints (Port 3000)

### Authentication
Semua endpoint API (kecuali `/health` dan `/status`) memerlukan API Key:
- Header: `X-API-Key: Indra`
- Query param: `?key=Indra`

### 1. Health Check
```
GET /health
```
**Response:**
```
ok=true; ready=true
```

### 2. Status Check
```
GET /status
```
**Response:**
```json
{
  "ok": true,
  "ready": true,
  "phoneNumber": "628xxxx"
}
```

### 3. Kirim Pesan (GET)
```
GET /pesan?wa=628123456789&pesan=Hello&key=Indra
```

**Parameters:**
- `wa` (required): Nomor WhatsApp (format: 628xxx)
- `pesan` (required): Pesan yang akan dikirim
- `key` (required): API Key

**Response Success:**
```json
{
  "ok": true,
  "to": "628123456789",
  "messageId": "3EB0xxxxx"
}
```

**Response Error:**
```json
{
  "ok": false,
  "error": "wa_not_ready"
}
```

### 4. Kirim Pesan (POST)
#### Single Number
```
POST /pesan
Headers: X-API-Key: Indra
Content-Type: application/json

Body:
{
  "wa": "628123456789",
  "pesan": "Hello dari API"
}
```

#### Multiple Numbers (Broadcast)
```
POST /pesan
Headers: X-API-Key: Indra
Content-Type: application/json

Body:
{
  "wa": ["628111111111", "628222222222", "628333333333"],
  "pesan": "Broadcast message"
}
```

**Response Success:**
```json
{
  "ok": true,
  "queued": 3,
  "results": [
    {
      "to": "628111111111",
      "ok": true,
      "messageId": "3EB0xxxxx",
      "error": null
    },
    {
      "to": "628222222222",
      "ok": true,
      "messageId": "3EB0yyyyy",
      "error": null
    },
    {
      "to": "628333333333",
      "ok": true,
      "messageId": "3EB0zzzzz",
      "error": null
    }
  ]
}
```

## Error Codes
- `401` - `unauthorized`: API Key salah atau tidak ada
- `400` - `invalid_input`: Format nomor atau pesan salah
- `503` - `wa_not_ready`: WhatsApp belum terkoneksi
- `413` - `too_many_recipients`: Melebihi batas MAX_PER_REQ (1500)
- `500` - `server_error`: Error server internal

## Format Nomor WhatsApp
Nomor harus dalam format:
- **Format valid**: `628123456789` (62 + nomor tanpa 0)
- **Auto-convert dari**: `08123456789` → `628123456789`
- **Auto-convert dari**: `+628123456789` → `628123456789`

## Rate Limiting
- Jeda antar pesan: **250ms** (configurable via `SEND_GAP_MS`)
- Maksimal nomor per request: **1500** (configurable via `MAX_PER_REQ`)
- Pesan menggunakan **queue system** untuk mencegah spam

## Security Features
1. **API Key authentication** untuk semua endpoint API
2. **Bcrypt password hashing** untuk admin dashboard
3. **Session management** dengan httpOnly cookies
4. **CORS protection** - hanya localhost dan LAN IPs
5. **Helmet.js** - security headers
6. **Input sanitization** - max 5000 karakter per pesan
7. **Rate limiting** via queue system

## CORS
Allowed origins:
- `http://localhost:3000`
- All LAN IPs: `http://[LAN_IP]:3000`

## Testing dengan cURL

### Test Health Check
```bash
curl http://localhost:3000/health
```

### Test Status
```bash
curl http://localhost:3000/status
```

### Test GET /pesan
```bash
curl "http://localhost:3000/pesan?wa=628123456789&pesan=Test%20message&key=Indra"
```

### Test POST /pesan (Single)
```bash
curl -X POST http://localhost:3000/pesan \
  -H "X-API-Key: Indra" \
  -H "Content-Type: application/json" \
  -d '{"wa":"628123456789","pesan":"Test dari API"}'
```

### Test POST /pesan (Broadcast)
```bash
curl -X POST http://localhost:3000/pesan \
  -H "X-API-Key: Indra" \
  -H "Content-Type: application/json" \
  -d '{"wa":["628111111111","628222222222"],"pesan":"Broadcast message"}'
```

### Test POST /pesan (Broadcast)
```bash
curl -X POST http://localhost:3000/pesan -H "Content-Type: application/json" -H "X-API-Key: YourAPIKEY" -d "{\"wa\":\"62811111111111\",\"pesan\":\"Halo test dari bot\"}"
```

## Testing dengan JavaScript (Fetch)
```javascript
// GET method
fetch('http://localhost:3000/pesan?wa=628123456789&pesan=Hello&key=Indra')
  .then(res => res.json())
  .then(data => console.log(data));

// POST method (single)
fetch('http://localhost:3000/pesan', {
  method: 'POST',
  headers: {
    'X-API-Key': 'Indra',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    wa: '628123456789',
    pesan: 'Hello dari JavaScript'
  })
})
  .then(res => res.json())
  .then(data => console.log(data));

// POST method (broadcast)
fetch('http://localhost:3000/pesan', {
  method: 'POST',
  headers: {
    'X-API-Key': 'Indra',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    wa: ['628111111111', '628222222222', '628333333333'],
    pesan: 'Broadcast message'
  })
})
  .then(res => res.json())
  .then(data => console.log(data));
```

## Troubleshooting

### Bot tidak ready
- Pastikan sudah login via dashboard (http://localhost:3001)
- Scan QR code dengan WhatsApp
- Check status: `GET /status`

### API Key error
- Pastikan menggunakan API Key yang benar: `Indra` (sesuai .env)
- Gunakan header `X-API-Key` atau query param `?key=`

### Nomor tidak valid
- Format harus: `628xxxxxxxxx` (tanpa +, tanpa 0 di depan)
- Minimal 10 digit, maksimal 15 digit

### Message tidak terkirim
- Check koneksi WhatsApp via dashboard
- Lihat logs di terminal untuk error details
- Pastikan nomor tujuan valid dan aktif WhatsApp

## Production Deployment

### Environment Variables
Update `.env` untuk production:
```env
NODE_ENV=production
API_KEY=your_secure_random_key_here
SESSION_SECRET=your_secure_session_secret
LOG_LEVEL=warn
```

### Security Checklist
- [ ] Change API_KEY to strong random string
- [ ] Change SESSION_SECRET to strong random string
- [ ] Change admin password via dashboard
- [ ] Enable HTTPS (use reverse proxy like nginx)
- [ ] Set proper CORS origins
- [ ] Enable rate limiting (consider express-rate-limit)
- [ ] Set up monitoring and logging
- [ ] Use PM2 or similar for process management

### Run with PM2
```bash
npm install -g pm2
pm2 start gateway.js --name whatsapp-gateway
pm2 save
pm2 startup
```

## Support
Untuk pertanyaan atau issue, silakan hubungi developer.
