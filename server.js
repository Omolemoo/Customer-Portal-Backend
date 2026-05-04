require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const USERS_FILE = path.join(__dirname, 'users.json');

// MIDDLEWARE - FIXED CORS
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:3001', 'http://127.0.0.1:3001' , 'http://localhost:3004', 'http://127.0.0.1:3004'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));

// Load/Save users
async function loadUsers() {
  try { return JSON.parse(await fs.readFile(USERS_FILE, 'utf8')); } 
  catch { return []; }
}
async function saveUsers(users) { await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2)); }

// REGISTER with VALIDATION
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // EMAIL: Gmail only
    if (!email.endsWith('@gmail.com')) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email must be Gmail (ends with @gmail.com)' 
      });
    }
    
    // PASSWORD: 8+ chars, 1 uppercase, 1 special
    const passRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8,}$/;
    if (!passRegex.test(password)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password: 8+ chars, 1 uppercase (A-Z), 1 special (!@#$%^&*)' 
      });
    }
    
    const users = await loadUsers();
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = { id: Date.now().toString(), name, email, password: hashedPassword };
    users.push(user);
    await saveUsers(users);
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name, email } });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// LOGIN with PASSWORD validation
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // EMAIL: Gmail only
    if (!email.endsWith('@gmail.com')) {
      return res.status(400).json({ 
        message: 'Gmail address required (@gmail.com)' 
      });
    }
    
    const users = await loadUsers();
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email } });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// PAYMENT
app.post('/api/payment', (req, res) => {
  const { amount, iban, cardNumber, cvv, expiry } = req.body;
  
  if (!/^\d+(\.\d{2})?$/.test(amount)) return res.status(400).json({error: 'Invalid amount'});
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/.test(iban)) return res.status(400).json({error: 'Invalid IBAN'});
  if (!/^\d{13,19}$/.test(cardNumber.replace(/\s/g, ''))) return res.status(400).json({error: 'Invalid card'});
  if (!/^\d{3,4}$/.test(cvv)) return res.status(400).json({error: 'Invalid CVV'});
  if (!/^(0[1-9]|1[0-2])\/\d{2}$/.test(expiry)) return res.status(400).json({error: 'Invalid expiry'});
  
  const paymentId = 'PAY' + Date.now();
  res.json({ success: true, paymentId, message: `✅ R${amount} processed` });
});

app.listen(5000, () => console.log('🚀 http://localhost:5000'));
// Add port 3001 to CORS
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3001'],
  credentials: true
}));