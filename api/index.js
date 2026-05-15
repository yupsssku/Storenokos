require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const xss = require('xss');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'rahasia_nokos_2024';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';
const PAKASIR_SLUG = process.env.PAKASIR_SLUG;
const PAKASIR_API_KEY = process.env.PAKASIR_API_KEY;
const JASAOTP_API_KEY = process.env.JASAOTP_API_KEY;
const NOKOS_PROFIT_PERCENT = parseInt(process.env.NOKOS_PROFIT_PERCENT) || 20;
const ADMIN_FEE = parseInt(process.env.ADMIN_FEE) || 0;

const DB_DIR = process.env.NODE_ENV === 'production' ? '/tmp' : path.join(__dirname, '..', 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

const DB = {
  users: path.join(DB_DIR, 'users.json'),
  transactions: path.join(DB_DIR, 'transactions.json'),
};

function readDB(file) {
  try {
    if (!fs.existsSync(file)) { fs.writeFileSync(file, '[]'); return []; }
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch { return []; }
}
function writeDB(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
const getUsers = () => readDB(DB.users);
const saveUsers = (d) => writeDB(DB.users, d);
const getTrx = () => readDB(DB.transactions);
const saveTrx = (d) => writeDB(DB.transactions, d);

function authMiddleware(req, res, next) {
  const token = req.body.token || req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.json({ success: false, message: 'Token tidak ada' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.json({ success: false, message: 'Token tidak valid atau sudah expired' }); }
}

function authAdmin(req, res, next) {
  const pass = req.body.password || req.headers['admin-auth'];
  if (pass === ADMIN_PASS) next();
  else res.json({ success: false, message: 'Akses ditolak' });
}

// ==========================================
// AUTH
// ==========================================
app.post('/api/register', async (req, res) => {
  const fullname = xss(String(req.body.fullname || '').trim());
  const username = xss(String(req.body.username || '').toLowerCase().trim().replace(/[^a-z0-9_]/g, ''));
  const phone = xss(String(req.body.phone || '').replace(/[^0-9]/g, ''));
  const password = String(req.body.password || '');

  if (!fullname || !username || !phone || !password)
    return res.json({ success: false, message: 'Semua field wajib diisi!' });
  if (username.length < 3)
    return res.json({ success: false, message: 'Username minimal 3 karakter!' });
  if (password.length < 6)
    return res.json({ success: false, message: 'Password minimal 6 karakter!' });
  if (phone.length < 9)
    return res.json({ success: false, message: 'Nomor HP tidak valid!' });

  const users = getUsers();
  if (users.find(u => u.username === username))
    return res.json({ success: false, message: 'Username sudah dipakai!' });
  if (users.find(u => u.phone === phone))
    return res.json({ success: false, message: 'Nomor HP sudah terdaftar!' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(), fullname, username, phone,
    password: hashed, balance: 0,
    created_at: new Date().toISOString()
  };
  users.push(newUser);
  saveUsers(users);
  res.json({ success: true, message: 'Registrasi berhasil! Silakan login.' });
});

app.post('/api/login', async (req, res) => {
  const username = xss(String(req.body.username || '').toLowerCase().trim());
  const password = String(req.body.password || '');
  const users = getUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.json({ success: false, message: 'Username atau password salah!' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.json({ success: false, message: 'Username atau password salah!' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  const safeUser = { ...user }; delete safeUser.password;
  res.json({ success: true, token, user: safeUser });
});

app.post('/api/get-user', authMiddleware, (req, res) => {
  const users = getUsers();
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.json({ success: false });
  const trxs = getTrx().filter(t => t.username === user.username && t.status === 'success');
  const totalDeposit = trxs.filter(t => t.type === 'deposit').reduce((a, b) => a + (b.amount || 0), 0);
  const totalSpent = trxs.filter(t => t.type !== 'deposit').reduce((a, b) => a + (b.amount || 0), 0);
  const safeUser = { ...user }; delete safeUser.password;
  res.json({
    success: true,
    user: { ...safeUser, stat_total_deposit: totalDeposit, stat_total_spent: totalSpent, stat_trx_count: trxs.length }
  });
});

// ==========================================
// DEPOSIT via PAKASIR
// ==========================================
app.post('/api/deposit', authMiddleware, async (req, res) => {
  const users = getUsers();
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

  const amount = parseInt(req.body.amount);
  if (!amount || amount < 1000)
    return res.json({ success: false, message: 'Minimal deposit Rp 1.000' });
  if (amount > 10000000)
    return res.json({ success: false, message: 'Maksimal deposit Rp 10.000.000' });

  const order_id = 'DEP-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();
  const amountToSend = amount + ADMIN_FEE;

  try {
    const response = await axios.post('https://app.pakasir.com/api/transactioncreate/qris', {
      project: PAKASIR_SLUG,
      order_id,
      amount: amountToSend,
      api_key: PAKASIR_API_KEY
    }, { timeout: 15000 });

    if (response.data && response.data.payment) {
      const payData = response.data.payment;
      const realAmount = payData.total_payment ? parseInt(payData.total_payment) : amountToSend;

      const trxs = getTrx();
      trxs.push({
        order_id, username: user.username, fullname: user.fullname,
        amount, pay_amount: realAmount, status: 'pending', type: 'deposit',
        qr_string: payData.payment_number, date: new Date().toISOString()
      });
      saveTrx(trxs);

      res.json({ success: true, qr_string: payData.payment_number, order_id, amount, pay_amount: realAmount });
    } else {
      res.json({ success: false, message: 'Gagal membuat tagihan QRIS' });
    }
  } catch (e) {
    res.json({ success: false, message: 'Gagal koneksi ke payment gateway' });
  }
});

app.post('/api/check-payment', async (req, res) => {
  const { order_id } = req.body;
  if (!order_id) return res.json({ success: false, message: 'Order ID tidak ada' });

  const trxs = getTrx();
  const trxIndex = trxs.findIndex(t => t.order_id === order_id);
  if (trxIndex === -1) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });

  const trx = trxs[trxIndex];
  if (trx.status === 'success') return res.json({ success: true, status: 'success' });
  if (trx.status === 'canceled') return res.json({ success: false, status: 'canceled', message: 'Transaksi dibatalkan' });

  try {
    const registeredAmount = trx.amount + ADMIN_FEE;
    const url = `https://app.pakasir.com/api/transactiondetail?project=${PAKASIR_SLUG}&amount=${registeredAmount}&order_id=${order_id}&api_key=${PAKASIR_API_KEY}`;
    const response = await axios.get(url, { timeout: 15000 });
    const pData = response.data.transaction;

    if (pData && ['completed', 'success', 'paid'].includes(pData.status)) {
      const users = getUsers();
      const userIndex = users.findIndex(u => u.username === trx.username);
      if (userIndex !== -1) {
        users[userIndex].balance += trx.amount;
        saveUsers(users);
      }
      trxs[trxIndex].status = 'success';
      saveTrx(trxs);
      return res.json({ success: true, status: 'success' });
    }
    res.json({ success: true, status: 'pending' });
  } catch {
    res.json({ success: false, message: 'Gagal cek status pembayaran' });
  }
});

// ==========================================
// NOKOS (JASAOTP)
// ==========================================
app.get('/api/nokos/negara', async (req, res) => {
  try {
    const response = await axios.get('https://api.jasaotp.id/v1/negara.php', { timeout: 15000 });
    if (response.data && response.data.success) {
      res.json({ success: true, data: response.data.data });
    } else {
      res.json({ success: false, data: [], message: 'Gagal memuat daftar negara' });
    }
  } catch {
    res.json({ success: false, data: [], message: 'Gagal koneksi ke provider' });
  }
});

app.post('/api/nokos/layanan', async (req, res) => {
  const { negara_id } = req.body;
  if (!negara_id) return res.json({ success: false, data: [] });
  try {
    const response = await axios.get(`https://api.jasaotp.id/v1/layanan.php?negara=${negara_id}`, { timeout: 15000 });
    if (response.data && response.data[negara_id]) {
      const layananList = [];
      for (const [kode, detail] of Object.entries(response.data[negara_id])) {
        const originalPrice = parseInt(detail.harga) || 0;
        const markedUpPrice = Math.ceil(originalPrice + (originalPrice * NOKOS_PROFIT_PERCENT / 100));
        layananList.push({
          kode, nama: detail.layanan || kode.toUpperCase(),
          harga: markedUpPrice, harga_asli: originalPrice, stok: detail.stok
        });
      }
      layananList.sort((a, b) => a.nama.localeCompare(b.nama));
      res.json({ success: true, data: layananList });
    } else {
      res.json({ success: false, data: [] });
    }
  } catch {
    res.json({ success: false, data: [] });
  }
});

app.post('/api/buy-nokos', authMiddleware, async (req, res) => {
  const { negara_id, negara_nama, operator, layanan_kode, layanan_nama, harga, method } = req.body;
  if (!negara_id || !layanan_kode || !harga || !method)
    return res.json({ success: false, message: 'Data tidak lengkap' });

  const users = getUsers();
  const userIndex = users.findIndex(u => u.username === req.user.username);
  if (userIndex === -1) return res.json({ success: false, message: 'User tidak ditemukan' });
  const user = users[userIndex];

  if (!JASAOTP_API_KEY) return res.json({ success: false, message: 'API Key provider belum dikonfigurasi' });
  const nominal = parseInt(harga);
  if (!nominal || nominal < 1) return res.json({ success: false, message: 'Harga tidak valid' });

  if (method === 'saldo') {
    if (user.balance < nominal) return res.json({ success: false, message: 'Saldo tidak cukup! Silakan deposit terlebih dahulu.' });

    try {
      const orderUrl = `https://api.jasaotp.id/v1/order.php?api_key=${JASAOTP_API_KEY}&negara=${negara_id}&layanan=${layanan_kode}&operator=${operator || ''}`;
      const orderResponse = await axios.get(orderUrl, { timeout: 20000 });

      if (orderResponse.data && orderResponse.data.success) {
        const providerOrderId = orderResponse.data.data.order_id;
        const nomorHp = orderResponse.data.data.number;

        users[userIndex].balance -= nominal;
        saveUsers(users);

        const order_id = 'NOKOS-' + Date.now();
        const trxs = getTrx();
        trxs.push({
          order_id, provider_oid: String(providerOrderId),
          username: user.username, fullname: user.fullname,
          amount: nominal, pay_amount: nominal,
          status: 'success', type: 'buy_nokos',
          product_data: {
            negara_id, negara_nama, operator,
            layanan_kode, layanan_nama,
            nomor: nomorHp, provider_order_id: providerOrderId, otp: null
          },
          date: new Date().toISOString()
        });
        saveTrx(trxs);

        res.json({
          success: true, type: 'instant',
          data: { order_id, nomor: nomorHp, provider_order_id: providerOrderId }
        });
      } else {
        res.json({ success: false, message: 'Gagal order ke provider: ' + (orderResponse.data?.message || 'Stok habis atau error') });
      }
    } catch {
      res.json({ success: false, message: 'Gagal koneksi ke provider. Coba lagi.' });
    }

  } else if (method === 'qris') {
    const order_id = 'NOKOS-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();
    const amountToSend = nominal + ADMIN_FEE;

    try {
      const response = await axios.post('https://app.pakasir.com/api/transactioncreate/qris', {
        project: PAKASIR_SLUG, order_id,
        amount: amountToSend, api_key: PAKASIR_API_KEY
      }, { timeout: 15000 });

      if (response.data && response.data.payment) {
        const payData = response.data.payment;
        const realAmount = payData.total_payment ? parseInt(payData.total_payment) : amountToSend;

        const trxs = getTrx();
        trxs.push({
          order_id, username: user.username, fullname: user.fullname,
          amount: nominal, pay_amount: realAmount,
          status: 'pending', type: 'buy_nokos',
          product_data: { negara_id, negara_nama, operator, layanan_kode, layanan_nama },
          qr_string: payData.payment_number, date: new Date().toISOString()
        });
        saveTrx(trxs);

        res.json({
          success: true, type: 'qris',
          qr_string: payData.payment_number,
          order_id, amount: nominal, pay_amount: realAmount
        });
      } else {
        res.json({ success: false, message: 'Gagal generate QRIS' });
      }
    } catch {
      res.json({ success: false, message: 'Gagal koneksi ke payment gateway' });
    }
  } else {
    res.json({ success: false, message: 'Metode pembayaran tidak valid' });
  }
});

app.post('/api/check-nokos-payment', async (req, res) => {
  const { order_id } = req.body;
  if (!order_id) return res.json({ success: false, message: 'Order ID tidak ada' });

  const trxs = getTrx();
  const trxIndex = trxs.findIndex(t => t.order_id === order_id);
  if (trxIndex === -1) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });

  const trx = trxs[trxIndex];
  if (trx.status === 'success') return res.json({ success: true, status: 'success', data: trx.product_data });

  try {
    const registeredAmount = trx.amount + ADMIN_FEE;
    const url = `https://app.pakasir.com/api/transactiondetail?project=${PAKASIR_SLUG}&amount=${registeredAmount}&order_id=${order_id}&api_key=${PAKASIR_API_KEY}`;
    const response = await axios.get(url, { timeout: 15000 });
    const pData = response.data.transaction;

    if (pData && ['completed', 'success', 'paid'].includes(pData.status)) {
      const { negara_id, operator, layanan_kode, layanan_nama, negara_nama } = trx.product_data;
      const orderUrl = `https://api.jasaotp.id/v1/order.php?api_key=${JASAOTP_API_KEY}&negara=${negara_id}&layanan=${layanan_kode}&operator=${operator || ''}`;
      const orderResponse = await axios.get(orderUrl, { timeout: 20000 });

      if (orderResponse.data && orderResponse.data.success) {
        const providerOrderId = orderResponse.data.data.order_id;
        const nomorHp = orderResponse.data.data.number;

        trxs[trxIndex].status = 'success';
        trxs[trxIndex].provider_oid = String(providerOrderId);
        trxs[trxIndex].product_data.nomor = nomorHp;
        trxs[trxIndex].product_data.provider_order_id = providerOrderId;
        saveTrx(trxs);

        return res.json({
          success: true, status: 'success',
          data: { nomor: nomorHp, provider_order_id: providerOrderId }
        });
      } else {
        return res.json({ success: false, message: 'Pembayaran diterima tapi gagal order ke provider. Hubungi admin.' });
      }
    }
    res.json({ success: true, status: 'pending' });
  } catch {
    res.json({ success: false, message: 'Gagal cek status' });
  }
});

app.post('/api/nokos/check-otp', authMiddleware, async (req, res) => {
  const { provider_order_id } = req.body;
  if (!provider_order_id) return res.json({ success: false, message: 'Order ID tidak ada' });
  try {
    const smsUrl = `https://api.jasaotp.id/v1/sms.php?api_key=${JASAOTP_API_KEY}&id=${provider_order_id}`;
    const response = await axios.get(smsUrl, { timeout: 15000 });
    if (response.data && response.data.success) {
      const otp = response.data.data.otp;
      const trxs = getTrx();
      const idx = trxs.findIndex(t => String(t.provider_oid) === String(provider_order_id));
      if (idx !== -1) { trxs[idx].product_data.otp = otp; saveTrx(trxs); }
      res.json({ success: true, otp });
    } else {
      res.json({ success: false, message: response.data?.message || 'OTP belum masuk, coba lagi' });
    }
  } catch {
    res.json({ success: false, message: 'Gagal cek OTP, coba lagi' });
  }
});

app.post('/api/nokos/cancel', authMiddleware, async (req, res) => {
  const { provider_order_id } = req.body;
  if (!provider_order_id) return res.json({ success: false, message: 'Order ID tidak ada' });
  try {
    const cancelUrl = `https://api.jasaotp.id/v1/cancel.php?api_key=${JASAOTP_API_KEY}&id=${provider_order_id}`;
    const response = await axios.get(cancelUrl, { timeout: 15000 });
    if (response.data && response.data.success) {
      const refundedAmount = response.data.data?.refunded_amount || 0;
      const trxs = getTrx();
      const idx = trxs.findIndex(t => String(t.provider_oid) === String(provider_order_id));
      if (idx !== -1) {
        if (refundedAmount > 0) {
          const users = getUsers();
          const uIdx = users.findIndex(u => u.username === trxs[idx].username);
          if (uIdx !== -1) { users[uIdx].balance += refundedAmount; saveUsers(users); }
        }
        trxs[idx].status = 'canceled';
        saveTrx(trxs);
      }
      res.json({ success: true, refunded: refundedAmount });
    } else {
      res.json({ success: false, message: response.data?.message || 'Gagal membatalkan order' });
    }
  } catch {
    res.json({ success: false, message: 'Gagal koneksi ke provider' });
  }
});

// ==========================================
// HISTORY
// ==========================================
app.post('/api/history', authMiddleware, (req, res) => {
  const trxs = getTrx()
    .filter(t => t.username === req.user.username)
    .sort((a, b) => new Date(b.date) - new Date(a.date))
    .slice(0, 100);
  res.json({ success: true, data: trxs });
});

// ==========================================
// ADMIN
// ==========================================
app.post('/api/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASS) res.json({ success: true, key: ADMIN_PASS });
  else res.json({ success: false, message: 'Password salah' });
});

app.post('/api/admin/stats', authAdmin, (req, res) => {
  const users = getUsers();
  const trxs = getTrx();
  const successTrx = trxs.filter(t => t.status === 'success');
  const totalIncome = successTrx.filter(t => t.type !== 'deposit').reduce((a, b) => a + (b.pay_amount || 0), 0);
  const totalDeposit = successTrx.filter(t => t.type === 'deposit').reduce((a, b) => a + (b.amount || 0), 0);
  const totalBalance = users.reduce((a, b) => a + (b.balance || 0), 0);
  res.json({
    success: true,
    total_users: users.length,
    total_trx: successTrx.filter(t => t.type !== 'deposit').length,
    total_income: totalIncome,
    total_deposit: totalDeposit,
    total_balance: totalBalance,
    pending_trx: trxs.filter(t => t.status === 'pending').length
  });
});

app.post('/api/admin/users', authAdmin, (req, res) => {
  const users = getUsers().map(u => { const s = { ...u }; delete s.password; return s; });
  res.json({ success: true, data: users });
});

app.post('/api/admin/transactions', authAdmin, (req, res) => {
  const trxs = getTrx().sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 300);
  res.json({ success: true, data: trxs });
});

app.post('/api/admin/topup-balance', authAdmin, (req, res) => {
  const { username, amount } = req.body;
  if (!username || !amount) return res.json({ success: false, message: 'Data tidak lengkap' });
  const users = getUsers();
  const idx = users.findIndex(u => u.username === username);
  if (idx === -1) return res.json({ success: false, message: 'User tidak ditemukan' });
  users[idx].balance += parseInt(amount);
  saveUsers(users);
  const trxs = getTrx();
  trxs.push({
    order_id: 'ADM-' + Date.now(), username, fullname: users[idx].fullname,
    amount: parseInt(amount), pay_amount: parseInt(amount),
    status: 'success', type: 'deposit', qr_string: '-',
    date: new Date().toISOString()
  });
  saveTrx(trxs);
  res.json({ success: true, message: `Saldo +Rp ${parseInt(amount).toLocaleString('id-ID')} berhasil ditambahkan` });
});

app.post('/api/admin/delete-user', authAdmin, (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: 'Username tidak ada' });
  const users = getUsers().filter(u => u.username !== username);
  saveUsers(users);
  res.json({ success: true, message: 'User berhasil dihapus' });
});

// ==========================================
// PUBLIC STATS
// ==========================================
app.get('/api/stats', (req, res) => {
  const users = getUsers();
  const trxs = getTrx().filter(t => t.status === 'success' && t.type !== 'deposit');
  res.json({ success: true, member: users.length, sukses: trxs.length });
});

// ==========================================
// SERVE HTML
// ==========================================
const publicDir = path.join(__dirname, '..', 'public');
app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(publicDir, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(publicDir, 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicDir, 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicDir, 'admin.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
module.exports = app;