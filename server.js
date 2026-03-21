require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mla_secret_2024';
const ADMIN_USER = process.env.ADMIN_USER || 'mla2024admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'mla2024admin';

// ── MIDDLEWARE ─────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// ── MONGODB ────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ── RATE LIMITING (in-memory) ──────────────────
const loginAttempts = new Map();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;

function checkRateLimit(key) {
  const now = Date.now();
  const attempts = loginAttempts.get(key);
  if (!attempts) return { allowed: true };
  const recent = attempts.filter(t => now - t < RATE_LIMIT_WINDOW);
  loginAttempts.set(key, recent);
  if (recent.length >= RATE_LIMIT_MAX) {
    const oldest = recent[0];
    const unlockIn = Math.ceil((RATE_LIMIT_WINDOW - (now - oldest)) / 1000);
    return { allowed: false, unlockIn };
  }
  return { allowed: true };
}
function recordAttempt(key) {
  const attempts = loginAttempts.get(key) || [];
  attempts.push(Date.now());
  loginAttempts.set(key, attempts);
}
function clearAttempts(key) { loginAttempts.delete(key); }

// ═══════════════════════════════════════════════
// SCHEMAS
// ═══════════════════════════════════════════════

const CompanySchema = new mongoose.Schema({
  name:      { type: String, required: true, unique: true },
  slug:      { type: String, required: true, unique: true, lowercase: true },
  createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  name:          { type: String, required: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  username:      { type: String, required: true, unique: true, lowercase: true },
  password:      { type: String, required: true },
  companyId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
  expiry:        { type: String, default: 'forever' },
  suspended:     { type: Boolean, default: false },
  emailVerified: { type: Boolean, default: false },
  verifyToken:   { type: String },
  featureTier:   { type: String, enum: ['standard', 'full'], default: 'standard' },
  features: {
    coverPage:      { type: Boolean, default: true },
    qrCode:         { type: Boolean, default: false },
    plan2d:         { type: Boolean, default: true },
    inspection:     { type: Boolean, default: true },
    quickCapture:   { type: Boolean, default: false },
    liveInspection: { type: Boolean, default: false },
    voiceToText:    { type: Boolean, default: false },
    timestamp:      { type: Boolean, default: false },
    comparison:     { type: Boolean, default: true },
    progressTracker:{ type: Boolean, default: true },
    exportPdf:      { type: Boolean, default: true },
    exportWord:     { type: Boolean, default: true },
    collaborate:    { type: Boolean, default: true },
    darkMode:       { type: Boolean, default: true }
  },
  lastLogin:      { type: Date },
  onboardingSeen: { type: Boolean, default: false },
  // Inspector custom logo for exports
  exportLogo:     { type: String }, // base64
  createdAt:      { type: Date, default: Date.now }
});

const ClientSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:          { type: String, required: true },
  contactPerson: { type: String },
  email:         { type: String },
  phone:         { type: String },
  address:       { type: String },
  logo:          { type: String },
  createdAt:     { type: Date, default: Date.now }
});

const CategorySchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  name:      { type: String, required: true },
  order:     { type: Number, default: 0 },
  enabled:   { type: Boolean, default: true },
  isDefault: { type: Boolean, default: false },
  // Snag item templates per category
  templates: [{ type: String }]
});

const ProjectSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
  clientId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Client' },
  name:      { type: String, required: true },
  ref:       { type: String },
  date:      { type: String },
  address:   { type: String },
  status:    { type: String, enum: ['draft', 'in_progress', 'under_review', 'completed', 'archived'], default: 'draft' },
  tags:      [{ type: String }],
  revision:  { type: Number, default: 0 },
  summary:   { type: String },
  appendix:  { type: String },
  cover: {
    clientLogo:   { type: String },
    projectTitle: { type: String },
    siteAddress:  { type: String }
  },
  collaborators: [{
    userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status:    { type: String, enum: ['pending', 'accepted', 'declined'], default: 'pending' },
    canExport: { type: Boolean, default: false },
    invitedAt: { type: Date, default: Date.now }
  }],
  visits: [{
    date:      { type: String },
    inspector: { type: String },
    notes:     { type: String },
    visitNumber: { type: Number, default: 1 },
    createdAt: { type: Date, default: Date.now }
  }],
  statusHistory: [{
    from:      { type: String },
    to:        { type: String },
    changedBy: { type: String },
    changedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const ItemSchema = new mongoose.Schema({
  projectId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  seq:          { type: Number },
  location:     { type: String },
  date:         { type: String },
  description:  { type: String },
  category:     { type: String, default: '' },
  priority:     { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  status:       { type: String, enum: ['open', 'closed', 'in_progress'], default: 'open' },
  contractor:   { type: String },
  notes:        { type: String },
  revisitFlag:  { type: Boolean, default: false },
  visitNumber:  { type: Number, default: 1 },
  photo:        { type: String },
  photoAfter:   { type: String },
  photoExtra:   { type: String },
  photoOriginal:      { type: String },
  photoAfterOriginal: { type: String },
  photoExtraOriginal: { type: String },
  photoExtras:        { type: [String], default: [], validate: { validator: v => v.length <= 10, message: 'Max 10 additional photos' } },
  linkedItems:  [{ type: mongoose.Schema.Types.ObjectId, ref: 'Item' }],
  pins:         { type: Array, default: [] },
  history: [{
    action:    { type: String },
    detail:    { type: String },
    timestamp: { type: Date, default: Date.now }
  }],
  deleted:    { type: Boolean, default: false },
  deletedAt:  { type: Date },
  createdAt:  { type: Date, default: Date.now }
});

const PlanSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:      { type: String, default: 'Floor Plan' },
  image:     { type: String },
  note:      { type: String, default: '' },
  order:     { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const AuditSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  userName:  { type: String },
  action:    { type: String, required: true },
  detail:    { type: String },
  ip:        { type: String },
  timestamp: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  broadcast:   { type: Boolean, default: false },
  message:     { type: String, required: true },
  read:        { type: Boolean, default: false },
  createdAt:   { type: Date, default: Date.now }
});

const ChatSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sender:    { type: String, enum: ['inspector', 'admin'], required: true },
  message:   { type: String, required: true },
  read:      { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Smart dropdown memory — per user, per field
const SmartDropdownSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  field:     { type: String, required: true }, // 'contractor', 'location', 'visitNumber'
  values:    [{ type: String }], // ordered by recency
  updatedAt: { type: Date, default: Date.now }
});

const Company      = mongoose.model('Company', CompanySchema);
const User         = mongoose.model('User', UserSchema);
const Client       = mongoose.model('Client', ClientSchema);
const Category     = mongoose.model('Category', CategorySchema);
const Project      = mongoose.model('Project', ProjectSchema);
const Item         = mongoose.model('Item', ItemSchema);
const Plan         = mongoose.model('Plan', PlanSchema);
const Audit        = mongoose.model('Audit', AuditSchema);
const Notification = mongoose.model('Notification', NotificationSchema);
const Chat         = mongoose.model('Chat', ChatSchema);
const SmartDropdown = mongoose.model('SmartDropdown', SmartDropdownSchema);

// ── HELPERS ───────────────────────────────────
function today() { return new Date().toISOString().split('T')[0]; }
function log(userId, userName, action, detail, ip) {
  Audit.create({ userId, userName, action, detail, ip }).catch(() => {});
}

// ── AUTH MIDDLEWARE ────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Not admin' });
    req.user = decoded;
    next();
  } catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

async function checkExpiry(req, res, next) {
  if (req.user.role === 'admin') return next();
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.suspended) return res.status(403).json({ error: 'suspended' });
    if (user.expiry !== 'forever' && new Date(user.expiry) < new Date()) {
      return res.status(403).json({ error: 'expired' });
    }
    next();
  } catch (e) { res.status(500).json({ error: e.message }); }
}

// ═══════════════════════════════════════════════
// HEALTH / ROOT
// ═══════════════════════════════════════════════
app.get('/', (req, res) => res.json({ status: 'MLA Inspection API running ✅', version: '3.0' }));
app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));

// ═══════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
  try {
    const { nameOrEmail, password } = req.body;
    if (!nameOrEmail || !password) return res.status(400).json({ error: 'Missing fields' });
    const loginKey = nameOrEmail.trim().toLowerCase();
    const ip = req.headers['x-forwarded-for'] || req.ip;
    const rl = checkRateLimit(loginKey);
    if (!rl.allowed) return res.status(429).json({ error: 'rate_limited', unlockIn: rl.unlockIn });

    if (loginKey === ADMIN_USER.toLowerCase() && password === ADMIN_PASS) {
      clearAttempts(loginKey);
      log(null, 'admin', 'login', 'Admin login', ip);
      return res.json({ role: 'admin', token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' }) });
    }

    const user = await User.findOne({ $or: [{ email: loginKey }, { username: loginKey }] });
    if (!user) { recordAttempt(loginKey); log(null, loginKey, 'login_failed', 'User not found', ip); return res.status(403).json({ error: 'locked' }); }
    const match = await bcrypt.compare(password, user.password);
    if (!match) { recordAttempt(loginKey); log(user._id, user.name, 'login_failed', 'Wrong password', ip); return res.status(401).json({ error: 'wrongpass' }); }
    if (user.suspended) return res.status(403).json({ error: 'suspended' });
    if (user.expiry !== 'forever' && new Date(user.expiry) < new Date()) return res.status(403).json({ error: 'expired' });

    // Expiry warning (3 days)
    let expiryWarning = null;
    if (user.expiry !== 'forever') {
      const daysLeft = Math.ceil((new Date(user.expiry) - new Date()) / 86400000);
      if (daysLeft <= 3 && daysLeft >= 0) expiryWarning = daysLeft;
    }

    user.lastLogin = new Date();
    await user.save();
    clearAttempts(loginKey);
    log(user._id, user.name, 'login', 'Successful login', ip);

    const token = jwt.sign({
      id: user._id, name: user.name, email: user.email,
      username: user.username, companyId: user.companyId,
      expiry: user.expiry, featureTier: user.featureTier, features: user.features
    }, JWT_SECRET, { expiresIn: '8h' });

    res.json({ token, name: user.name, id: user._id, expiry: user.expiry,
      companyId: user.companyId, featureTier: user.featureTier,
      features: user.features, onboardingSeen: user.onboardingSeen,
      exportLogo: user.exportLogo, expiryWarning });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/onboarding-seen', auth, async (req, res) => {
  try { await User.findByIdAndUpdate(req.user.id, { onboardingSeen: true }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/profile', auth, checkExpiry, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, { password: 0 }).populate('companyId');
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Upload inspector export logo
app.put('/api/user/export-logo', auth, async (req, res) => {
  try {
    const { logo } = req.body;
    await User.findByIdAndUpdate(req.user.id, { exportLogo: logo });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/notifications', auth, async (req, res) => {
  try {
    const notifs = await Notification.find({
      $or: [{ recipientId: req.user.id }, { companyId: req.user.companyId, broadcast: true }],
      read: false
    }).sort({ createdAt: -1 }).limit(20);
    res.json(notifs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/user/notifications/:id/read', auth, async (req, res) => {
  try { await Notification.findByIdAndUpdate(req.params.id, { read: true }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// SMART DROPDOWNS
// ═══════════════════════════════════════════════

app.get('/api/user/dropdowns', auth, async (req, res) => {
  try {
    const docs = await SmartDropdown.find({ userId: req.user.id });
    const result = {};
    docs.forEach(d => { result[d.field] = d.values; });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/dropdowns', auth, async (req, res) => {
  try {
    const { field, value } = req.body;
    if (!field || !value) return res.status(400).json({ error: 'field and value required' });
    let doc = await SmartDropdown.findOne({ userId: req.user.id, field });
    if (!doc) {
      doc = new SmartDropdown({ userId: req.user.id, field, values: [] });
    }
    // Add to front, dedupe, cap at 20
    doc.values = [value, ...doc.values.filter(v => v !== value)].slice(0, 20);
    doc.updatedAt = new Date();
    await doc.save();
    res.json(doc.values);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — COMPANY ROUTES
// ═══════════════════════════════════════════════

app.get('/api/admin/companies', adminAuth, async (req, res) => {
  try {
    const companies = await Company.find().sort({ name: 1 });
    const result = await Promise.all(companies.map(async c => {
      const userCount = await User.countDocuments({ companyId: c._id });
      return { ...c.toObject(), userCount };
    }));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/companies', adminAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const company = await Company.create({ name, slug });
    const defaults = ['Electrical', 'Plumbing', 'Structural', 'Finishing', 'Landscaping', 'Hardscape', 'Irrigation', 'Drainage', 'General'];
    await Category.insertMany(defaults.map((n, i) => ({ companyId: company._id, name: n, order: i, isDefault: true, enabled: true })));
    log(null, 'admin', 'company_created', `Company: ${name}`, req.ip);
    res.json(company);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/companies/:id', adminAuth, async (req, res) => {
  try {
    await Company.deleteOne({ _id: req.params.id });
    log(null, 'admin', 'company_deleted', `Company ID: ${req.params.id}`, req.ip);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — USER (INSPECTOR) ROUTES
// ═══════════════════════════════════════════════

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }).populate('companyId').sort({ createdAt: -1 });
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { name, email, username, password, companyId, expiry, featureTier, features } = req.body;
    if (!name || !email || !username || !password || !companyId) return res.status(400).json({ error: 'Missing required fields' });
    const hashed = await bcrypt.hash(password, 10);
    const existing = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
    if (existing) {
      existing.name = name; existing.password = hashed; existing.companyId = companyId;
      existing.expiry = expiry || 'forever'; existing.featureTier = featureTier || 'standard';
      if (features) existing.features = { ...existing.features.toObject(), ...features };
      await existing.save();
      log(null, 'admin', 'user_updated', `User: ${name} (${email})`, req.ip);
      return res.json({ message: 'User updated', user: existing });
    }
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const user = await User.create({ name, email: email.toLowerCase(), username: username.toLowerCase(), password: hashed, companyId, expiry: expiry || 'forever', featureTier: featureTier || 'standard', features: features || {}, verifyToken });
    log(null, 'admin', 'user_created', `User: ${name} (${email})`, req.ip);
    res.json({ message: 'User created', user, verifyToken });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const updates = { ...req.body };
    if (updates.password) updates.password = await bcrypt.hash(updates.password, 10);
    const user = await User.findByIdAndUpdate(req.params.id, { $set: updates }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    log(null, 'admin', 'user_updated', `User: ${user.name}`, req.ip);
    res.json(user);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id/suspend', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    user.suspended = !user.suspended; await user.save();
    log(null, 'admin', user.suspended ? 'user_suspended' : 'user_unsuspended', `User: ${user.name}`, req.ip);
    res.json({ suspended: user.suspended });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Renew — accept duration string or date
app.patch('/api/admin/users/:id/renew', adminAuth, async (req, res) => {
  try {
    const { expiry, duration } = req.body;
    let newExpiry = expiry;
    if (duration && !expiry) {
      if (duration === 'forever') { newExpiry = 'forever'; }
      else {
        const map = { '3d': 3, '7d': 7, '14d': 14, '1m': 30, '3m': 90, '6m': 180, '1y': 365 };
        const d = new Date();
        d.setDate(d.getDate() + (map[duration] || 30));
        newExpiry = d.toISOString().split('T')[0];
      }
    }
    const user = await User.findByIdAndUpdate(req.params.id, { expiry: newExpiry || 'forever' }, { new: true }).select('-password');
    if (!user) return res.status(404).json({ error: 'Not found' });
    log(null, 'admin', 'user_renewed', `User: ${user.name} until ${newExpiry}`, req.ip);
    res.json(user);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users/bulk-renew', adminAuth, async (req, res) => {
  try {
    const { userIds, expiry } = req.body;
    await User.updateMany({ _id: { $in: userIds } }, { expiry: expiry || 'forever' });
    log(null, 'admin', 'bulk_renew', `${userIds.length} users renewed`, req.ip);
    res.json({ ok: true, count: userIds.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    const uid = req.params.id;
    const projects = await Project.find({ userId: uid });
    const projectIds = projects.map(p => p._id);
    const itemResult = await Item.deleteMany({ projectId: { $in: projectIds } });
    const planResult = await Plan.deleteMany({ projectId: { $in: projectIds } });
    const projResult = await Project.deleteMany({ userId: uid });
    const clientResult = await Client.deleteMany({ userId: uid });
    await Chat.deleteMany({ userId: uid });
    await Notification.deleteMany({ recipientId: uid });
    await SmartDropdown.deleteMany({ userId: uid });
    await User.deleteOne({ _id: uid });
    log(null, 'admin', 'user_deleted', `User: ${user.name} — ${projResult.deletedCount} projects, ${itemResult.deletedCount} items removed`, req.ip);
    res.json({ ok: true, deleted: { projects: projResult.deletedCount, items: itemResult.deletedCount, plans: planResult.deletedCount, clients: clientResult.deletedCount } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — CLIENT ROUTES
// ═══════════════════════════════════════════════

app.get('/api/admin/clients', adminAuth, async (req, res) => {
  try {
    const { userId } = req.query;
    const filter = userId ? { userId } : {};
    const clients = await Client.find(filter).populate('userId', 'name email').sort({ name: 1 });
    res.json(clients);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — CATEGORY ROUTES (with templates)
// ═══════════════════════════════════════════════

app.get('/api/admin/categories', adminAuth, async (req, res) => {
  try {
    const { companyId } = req.query;
    const filter = companyId ? { companyId } : {};
    const cats = await Category.find(filter).sort({ order: 1 });
    res.json(cats);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/categories', adminAuth, async (req, res) => {
  try { const cat = await Category.create(req.body); res.json(cat); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/categories/:id', adminAuth, async (req, res) => {
  try {
    const cat = await Category.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
    res.json(cat);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update category templates
app.put('/api/admin/categories/:id/templates', adminAuth, async (req, res) => {
  try {
    const { templates } = req.body;
    const cat = await Category.findByIdAndUpdate(req.params.id, { $set: { templates } }, { new: true });
    res.json(cat);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/categories/:id', adminAuth, async (req, res) => {
  try { await Category.deleteOne({ _id: req.params.id }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/categories/reorder', adminAuth, async (req, res) => {
  try {
    const { ordered } = req.body;
    await Promise.all(ordered.map(c => Category.findByIdAndUpdate(c.id, { order: c.order })));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — STATS & STORAGE
// ═══════════════════════════════════════════════

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }).populate('companyId');
    const stats = await Promise.all(users.map(async u => {
      const projects = await Project.find({ userId: u._id });
      const items = await Item.find({ userId: u._id, deleted: { $ne: true } });
      let storageBytes = 0;
      items.forEach(i => {
        ['photo', 'photoAfter', 'photoExtra'].forEach(f => { if (i[f]) storageBytes += Math.round(i[f].length * 0.75); });
      });
      const plans = await Plan.find({ userId: u._id });
      plans.forEach(p => { if (p.image) storageBytes += Math.round(p.image.length * 0.75); });
      // Expiry warning
      let daysLeft = null;
      if (u.expiry !== 'forever') daysLeft = Math.ceil((new Date(u.expiry) - new Date()) / 86400000);
      return {
        _id: u._id, name: u.name, email: u.email, company: u.companyId?.name || 'Unknown',
        expiry: u.expiry, daysLeft, suspended: u.suspended, featureTier: u.featureTier,
        lastLogin: u.lastLogin, projects: projects.length, items: items.length,
        storageMB: parseFloat((storageBytes / (1024 * 1024)).toFixed(2))
      };
    }));
    stats.sort((a, b) => b.storageMB - a.storageMB);
    const totalMB = parseFloat(stats.reduce((s, u) => s + u.storageMB, 0).toFixed(2));
    const limitMB = 512;
    const totalProjects = await Project.countDocuments();
    const totalItems = await Item.countDocuments({ deleted: { $ne: true } });
    const openItems = await Item.countDocuments({ status: 'open', deleted: { $ne: true } });
    const closedItems = await Item.countDocuments({ status: 'closed', deleted: { $ne: true } });
    const activeInspectors = await User.countDocuments({ suspended: false, $or: [{ expiry: 'forever' }, { expiry: { $gte: today() } }] });
    const expiredInspectors = await User.countDocuments({ $and: [{ expiry: { $ne: 'forever' } }, { expiry: { $lt: today() } }] });
    res.json({ users: stats, totalMB, limitMB, usedPct: parseFloat(((totalMB / limitMB) * 100).toFixed(1)), totals: { projects: totalProjects, items: totalItems, openItems, closedItems, activeInspectors, expiredInspectors } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — NOTIFICATIONS
// ═══════════════════════════════════════════════

app.post('/api/admin/notifications', adminAuth, async (req, res) => {
  try {
    const { recipientId, companyId, broadcast, message } = req.body;
    const notif = await Notification.create({ recipientId, companyId, broadcast: !!broadcast, message });
    res.json(notif);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — AUDIT LOG
// ═══════════════════════════════════════════════

app.get('/api/admin/audit', adminAuth, async (req, res) => {
  try {
    const { limit = 100, skip = 0, action, userId } = req.query;
    const filter = {};
    if (action) filter.action = { $regex: action, $options: 'i' };
    if (userId) filter.userId = userId;
    const logs = await Audit.find(filter).sort({ timestamp: -1 }).skip(Number(skip)).limit(Number(limit));
    const total = await Audit.countDocuments(filter);
    res.json({ logs, total });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — CHAT (Inspector-to-Admin)
// ═══════════════════════════════════════════════

app.get('/api/admin/chat/:userId', adminAuth, async (req, res) => {
  try {
    const msgs = await Chat.find({ userId: req.params.userId }).sort({ createdAt: 1 }).limit(200);
    // Mark all as read from admin's side
    await Chat.updateMany({ userId: req.params.userId, sender: 'inspector', read: false }, { read: true });
    res.json(msgs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/chat/:userId', adminAuth, async (req, res) => {
  try {
    const msg = await Chat.create({ userId: req.params.userId, sender: 'admin', message: req.body.message });
    res.json(msg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get unread counts per user (for admin inbox)
app.get('/api/admin/chat-unread', adminAuth, async (req, res) => {
  try {
    const unread = await Chat.aggregate([
      { $match: { sender: 'inspector', read: false } },
      { $group: { _id: '$userId', count: { $sum: 1 } } }
    ]);
    const result = {};
    unread.forEach(u => { result[u._id.toString()] = u.count; });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Inspector chat
app.get('/api/user/chat', auth, async (req, res) => {
  try {
    const msgs = await Chat.find({ userId: req.user.id }).sort({ createdAt: 1 }).limit(200);
    await Chat.updateMany({ userId: req.user.id, sender: 'admin', read: false }, { read: true });
    res.json(msgs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/chat', auth, async (req, res) => {
  try {
    const msg = await Chat.create({ userId: req.user.id, sender: 'inspector', message: req.body.message });
    res.json(msg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Inspector unread count
app.get('/api/user/chat-unread', auth, async (req, res) => {
  try {
    const count = await Chat.countDocuments({ userId: req.user.id, sender: 'admin', read: false });
    res.json({ count });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — PROJECT BROWSER
// ═══════════════════════════════════════════════

app.get('/api/admin/projects', adminAuth, async (req, res) => {
  try {
    const { companyId, userId, status, tag } = req.query;
    const filter = {};
    if (companyId) filter.companyId = companyId;
    if (userId) filter.userId = userId;
    if (status) filter.status = status;
    if (tag) filter.tags = tag;
    const projects = await Project.find(filter).populate('userId', 'name email').populate('clientId', 'name').populate('companyId', 'name').sort({ createdAt: -1 });
    res.json(projects);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/projects/:id/flag', adminAuth, async (req, res) => {
  try { await Project.findByIdAndUpdate(req.params.id, { flagged: req.body.flagged }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/projects/:id/status', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    project.statusHistory.push({ from: project.status, to: status, changedBy: 'admin' });
    project.status = status; await project.save(); res.json(project);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ADMIN — BACKUP
// ═══════════════════════════════════════════════

app.get('/api/admin/backup', adminAuth, async (req, res) => {
  try {
    const [users, companies, clients, categories, projects] = await Promise.all([
      User.find({}, { password: 0 }), Company.find(), Client.find({}, { logo: 0 }), Category.find(), Project.find({}, { 'cover.clientLogo': 0 })
    ]);
    res.json({ exportedAt: new Date().toISOString(), users, companies, clients, categories, projects });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// PROJECT ROUTES
// ═══════════════════════════════════════════════

app.get('/api/projects', auth, checkExpiry, async (req, res) => {
  try {
    const own = await Project.find({ userId: req.user.id }).sort({ createdAt: -1 });
    const collaborated = await Project.find({ 'collaborators.userId': req.user.id, 'collaborators.status': 'accepted' }).sort({ createdAt: -1 });

    const enrich = async (projects) => {
      return Promise.all(projects.map(async p => {
        const items = await Item.find({ projectId: p._id, deleted: { $ne: true } });
        const obj = p.toObject();
        obj.total = items.length;
        obj.open = items.filter(i => i.status === 'open').length;
        obj.closed = items.filter(i => i.status === 'closed').length;
        obj.inProgress = items.filter(i => i.status === 'in_progress').length;
        obj.criticalCount = items.filter(i => i.priority === 'critical' && i.status !== 'closed').length;
        // Before/After progress: items with both photos
        obj.withBefore = items.filter(i => i.photo).length;
        obj.withAfter = items.filter(i => i.photoAfter).length;
        return obj;
      }));
    };

    const ownEnriched = await enrich(own);
    const collabEnriched = (await enrich(collaborated)).map(p => ({ ...p, isCollab: true }));
    res.json([...ownEnriched, ...collabEnriched]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects', auth, checkExpiry, async (req, res) => {
  try {
    const { name, ref, date, address, clientId, tags } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const project = await Project.create({
      userId: req.user.id, companyId: req.user.companyId, clientId,
      name, ref, date: date || today(), address, tags: tags || [], status: 'draft',
      statusHistory: [{ from: null, to: 'draft', changedBy: req.user.name }]
    });
    log(req.user.id, req.user.name, 'project_created', `Project: ${name}`, req.ip);
    res.json(project);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/projects/:id', auth, checkExpiry, async (req, res) => {
  try {
    const project = await Project.findOne({ _id: req.params.id, userId: req.user.id });
    if (!project) return res.status(404).json({ error: 'Not found' });
    const updates = req.body;
    if (updates.status && updates.status !== project.status) {
      if (updates.status === 'completed') return res.status(403).json({ error: 'Only admin can mark as completed' });
      project.statusHistory.push({ from: project.status, to: updates.status, changedBy: req.user.name });
    }
    Object.assign(project, updates); await project.save(); res.json(project);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/:id/duplicate', auth, checkExpiry, async (req, res) => {
  try {
    const orig = await Project.findOne({ _id: req.params.id, userId: req.user.id });
    if (!orig) return res.status(404).json({ error: 'Not found' });
    const dup = await Project.create({
      userId: req.user.id, companyId: req.user.companyId, clientId: orig.clientId,
      name: orig.name + ' (Copy)', ref: '', date: today(), address: orig.address,
      tags: orig.tags, status: 'draft', cover: orig.cover,
      statusHistory: [{ from: null, to: 'draft', changedBy: req.user.name }]
    });
    const plans = await Plan.find({ projectId: orig._id });
    for (const plan of plans) { await Plan.create({ projectId: dup._id, userId: req.user.id, name: plan.name, order: plan.order }); }
    log(req.user.id, req.user.name, 'project_duplicated', `From: ${orig.name}`, req.ip);
    res.json(dup);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/projects/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id).populate('userId', 'name');
    if (!project) return res.status(404).json({ error: 'Not found' });
    if (project.userId._id.toString() !== req.user.id) {
      return res.status(403).json({ error: 'not_owner', ownerName: project.userId.name });
    }
    await Project.deleteOne({ _id: req.params.id });
    await Item.deleteMany({ projectId: req.params.id });
    await Plan.deleteMany({ projectId: req.params.id });
    log(req.user.id, req.user.name, 'project_deleted', `Project ID: ${req.params.id}`, req.ip);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── COLLABORATION ────────────────────────────

app.get('/api/projects/:id/collaborators', auth, checkExpiry, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id).populate('collaborators.userId', 'name email username');
    if (!project) return res.status(404).json({ error: 'Not found' });
    res.json(project.collaborators);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Invite collaborator by username/email
app.post('/api/projects/:id/invite', auth, checkExpiry, async (req, res) => {
  try {
    const { usernameOrEmail } = req.body;
    const project = await Project.findOne({ _id: req.params.id, userId: req.user.id });
    if (!project) return res.status(404).json({ error: 'Not found or not owner' });
    const invitee = await User.findOne({ $or: [{ email: usernameOrEmail?.toLowerCase() }, { username: usernameOrEmail?.toLowerCase() }] });
    if (!invitee) return res.status(404).json({ error: 'User not found' });
    if (invitee._id.toString() === req.user.id) return res.status(400).json({ error: 'Cannot invite yourself' });
    const already = project.collaborators.find(c => c.userId?.toString() === invitee._id.toString());
    if (already) return res.status(400).json({ error: 'Already invited' });
    project.collaborators.push({ userId: invitee._id, status: 'pending' });
    await project.save();
    // Notify
    await Notification.create({ recipientId: invitee._id, message: `${req.user.name} invited you to project: ${project.name}` });
    log(req.user.id, req.user.name, 'collab_invited', `Invited ${invitee.name} to ${project.name}`, req.ip);
    res.json({ ok: true, invitee: { name: invitee.name, email: invitee.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Accept/decline collaboration invite
app.patch('/api/projects/:id/collab-respond', auth, checkExpiry, async (req, res) => {
  try {
    const { action } = req.body; // 'accept' | 'decline'
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    const collab = project.collaborators.find(c => c.userId?.toString() === req.user.id);
    if (!collab) return res.status(404).json({ error: 'No invite found' });
    collab.status = action === 'accept' ? 'accepted' : 'declined';
    await project.save();
    log(req.user.id, req.user.name, `collab_${collab.status}`, `Project: ${project.name}`, req.ip);
    res.json({ ok: true, status: collab.status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Remove collaborator
app.delete('/api/projects/:id/collaborators/:userId', auth, checkExpiry, async (req, res) => {
  try {
    const project = await Project.findOne({ _id: req.params.id, userId: req.user.id });
    if (!project) return res.status(404).json({ error: 'Not found' });
    project.collaborators = project.collaborators.filter(c => c.userId?.toString() !== req.params.userId);
    await project.save(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get pending invites for current user
app.get('/api/user/invites', auth, async (req, res) => {
  try {
    const projects = await Project.find({ 'collaborators.userId': req.user.id, 'collaborators.status': 'pending' }).select('name ref collaborators userId').populate('userId', 'name');
    const invites = projects.map(p => {
      const collab = p.collaborators.find(c => c.userId?.toString() === req.user.id);
      return { projectId: p._id, projectName: p.name, projectRef: p.ref, ownerName: p.userId?.name, invitedAt: collab?.invitedAt };
    });
    res.json(invites);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── VISITS ───────────────────────────────────

app.get('/api/projects/:id/visits', auth, checkExpiry, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    res.json(project.visits || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/:id/visits', auth, checkExpiry, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    const { date, inspector, notes, visitNumber } = req.body;
    project.visits.push({ date: date || today(), inspector: inspector || req.user.name, notes, visitNumber: visitNumber || (project.visits.length + 1) });
    await project.save(); res.json(project.visits);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// ITEM ROUTES
// ═══════════════════════════════════════════════

app.get('/api/projects/:projectId/items', auth, checkExpiry, async (req, res) => {
  try {
    const { includeDeleted } = req.query;
    const filter = { projectId: req.params.projectId };
    if (!includeDeleted) filter.deleted = { $ne: true };
    const items = await Item.find(filter).sort({ seq: 1 });
    res.json(items);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/projects/:projectId/items/next-seq', auth, async (req, res) => {
  try {
    const lastItem = await Item.findOne({ projectId: req.params.projectId }).sort({ seq: -1 });
    res.json({ nextSeq: (lastItem?.seq || 0) + 1 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/:projectId/items', auth, checkExpiry, async (req, res) => {
  try {
    const item = await Item.create({
      projectId: req.params.projectId, userId: req.user.id,
      seq: req.body.seq, location: req.body.location, date: req.body.date || today(),
      description: req.body.description, category: req.body.category || '',
      priority: req.body.priority || 'medium', status: req.body.status || 'open',
      contractor: req.body.contractor, notes: req.body.notes,
      photo: req.body.photo || null, photoAfter: req.body.photoAfter || null,
      photoExtra: req.body.photoExtra || null, visitNumber: req.body.visitNumber || 1,
      history: [{ action: 'created', detail: `Item #${req.body.seq} created`, timestamp: new Date() }]
    });
    // Update smart dropdowns
    if (req.body.contractor) {
      await SmartDropdown.findOneAndUpdate({ userId: req.user.id, field: 'contractor' }, { $push: { values: { $each: [req.body.contractor], $position: 0 } }, $set: { updatedAt: new Date() } }, { upsert: true });
    }
    if (req.body.location) {
      await SmartDropdown.findOneAndUpdate({ userId: req.user.id, field: 'location' }, { $push: { values: { $each: [req.body.location], $position: 0 } }, $set: { updatedAt: new Date() } }, { upsert: true });
    }
    res.json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/items/:id', auth, checkExpiry, async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Not found' });
    const changes = [];
    if (req.body.status && req.body.status !== item.status) changes.push({ action: 'status_changed', detail: `${item.status} → ${req.body.status}` });
    if (req.body.photo && !item.photo) changes.push({ action: 'photo_added', detail: 'Before photo added' });
    if (req.body.photoAfter && !item.photoAfter) changes.push({ action: 'photo_added', detail: 'After photo added' });
    if (req.body.photoExtra && !item.photoExtra) changes.push({ action: 'photo_added', detail: 'Additional photo added' });
    if (req.body.description && req.body.description !== item.description) changes.push({ action: 'edited', detail: 'Description updated' });
    if (req.body.category && req.body.category !== item.category) changes.push({ action: 'edited', detail: `Category: ${req.body.category}` });
    if (req.body.priority && req.body.priority !== item.priority) changes.push({ action: 'edited', detail: `Priority: ${req.body.priority}` });
    Object.assign(item, req.body);
    if (changes.length) item.history = [...(item.history || []), ...changes.map(c => ({ ...c, timestamp: new Date() }))];
    await item.save();
    // Update smart dropdowns
    if (req.body.contractor) { await SmartDropdown.findOneAndUpdate({ userId: req.user.id || item.userId, field: 'contractor' }, { $push: { values: { $each: [req.body.contractor], $position: 0 } }, $set: { updatedAt: new Date() } }, { upsert: true }); }
    if (req.body.location) { await SmartDropdown.findOneAndUpdate({ userId: req.user.id || item.userId, field: 'location' }, { $push: { values: { $each: [req.body.location], $position: 0 } }, $set: { updatedAt: new Date() } }, { upsert: true }); }
    res.json(item);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Duplicate item
app.post('/api/items/:id/duplicate', auth, checkExpiry, async (req, res) => {
  try {
    const orig = await Item.findById(req.params.id);
    if (!orig) return res.status(404).json({ error: 'Not found' });
    const lastItem = await Item.findOne({ projectId: orig.projectId }).sort({ seq: -1 });
    const nextSeq = (lastItem?.seq || 0) + 1;
    const dup = await Item.create({
      projectId: orig.projectId, userId: orig.userId, seq: nextSeq,
      location: orig.location, date: today(), description: orig.description + ' (copy)',
      category: orig.category, priority: orig.priority, status: 'open',
      contractor: orig.contractor, visitNumber: orig.visitNumber,
      history: [{ action: 'created', detail: `Duplicated from INS-${String(orig.seq).padStart(3,'0')}`, timestamp: new Date() }]
    });
    res.json(dup);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/items/:id', auth, async (req, res) => {
  try { await Item.findByIdAndUpdate(req.params.id, { deleted: true, deletedAt: new Date() }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/items/:id/restore', auth, async (req, res) => {
  try { await Item.findByIdAndUpdate(req.params.id, { deleted: false, deletedAt: null }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/items/:id/permanent', auth, async (req, res) => {
  try { await Item.deleteOne({ _id: req.params.id }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/items/:id/link', auth, checkExpiry, async (req, res) => {
  try {
    const { targetId } = req.body;
    if (!targetId) return res.status(400).json({ error: 'targetId required' });
    const source = await Item.findById(req.params.id);
    const target = await Item.findById(targetId);
    if (!source || !target) return res.status(404).json({ error: 'Item not found' });
    if (!source.linkedItems.includes(targetId)) {
      source.linkedItems.push(targetId);
      source.history.push({ action: 'linked', detail: `Linked to INS-${String(target.seq).padStart(3,'0')}`, timestamp: new Date() });
      await source.save();
    }
    if (!target.linkedItems.includes(req.params.id)) {
      target.linkedItems.push(req.params.id);
      target.history.push({ action: 'linked', detail: `Linked to INS-${String(source.seq).padStart(3,'0')}`, timestamp: new Date() });
      await target.save();
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/items/:id/unlink', auth, checkExpiry, async (req, res) => {
  try {
    const { targetId } = req.body;
    await Item.findByIdAndUpdate(req.params.id, { $pull: { linkedItems: targetId } });
    await Item.findByIdAndUpdate(targetId, { $pull: { linkedItems: req.params.id } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/items/bulk-status', auth, checkExpiry, async (req, res) => {
  try {
    const { itemIds, status } = req.body;
    await Item.updateMany({ _id: { $in: itemIds } }, { $set: { status }, $push: { history: { action: 'status_changed', detail: `Bulk changed to ${status}`, timestamp: new Date() } } });
    res.json({ ok: true, count: itemIds.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// PLAN ROUTES
// ═══════════════════════════════════════════════

app.get('/api/projects/:projectId/plans', auth, checkExpiry, async (req, res) => {
  try { const plans = await Plan.find({ projectId: req.params.projectId }).sort({ order: 1, createdAt: 1 }); res.json(plans); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/:projectId/plans', auth, checkExpiry, async (req, res) => {
  try {
    const plan = await Plan.create({ projectId: req.params.projectId, userId: req.user.id, name: req.body.name || 'Floor Plan', image: req.body.image || null, order: req.body.order || 0 });
    res.json(plan);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/plans/:id', auth, checkExpiry, async (req, res) => {
  try { const plan = await Plan.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true }); res.json(plan); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/plans/:id', auth, async (req, res) => {
  try {
    await Plan.deleteOne({ _id: req.params.id });
    await Item.updateMany({}, { $pull: { pins: { planId: req.params.id } } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// CATEGORIES (Inspector)
// ═══════════════════════════════════════════════

app.get('/api/categories', auth, async (req, res) => {
  try {
    const cats = await Category.find({ companyId: req.user.companyId, enabled: true }).sort({ order: 1 });
    res.json(cats);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// CLIENTS (Inspector)
// ═══════════════════════════════════════════════

app.get('/api/clients', auth, async (req, res) => {
  try { const clients = await Client.find({ userId: req.user.id }).sort({ name: 1 }); res.json(clients); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clients', auth, async (req, res) => {
  try { const client = await Client.create({ ...req.body, userId: req.user.id }); res.json(client); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/clients/:id', auth, async (req, res) => {
  try {
    const client = await Client.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { $set: req.body }, { new: true });
    if (!client) return res.status(404).json({ error: 'Not found' });
    res.json(client);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/clients/:id', auth, async (req, res) => {
  try { await Client.deleteOne({ _id: req.params.id, userId: req.user.id }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// WORD EXPORT
// ═══════════════════════════════════════════════

app.post('/api/projects/:id/export/word', auth, checkExpiry, async (req, res) => {
  try {
    const {
      Document, Paragraph, Table, TableRow, TableCell,
      TextRun, ImageRun, Header, Footer, PageNumber,
      AlignmentType, WidthType, BorderStyle, HeadingLevel,
      ShadingType, PageBreak, VerticalAlign, TableLayoutType,
      TableOfContents, StyleLevel, Packer
    } = require('docx');

    const project = await Project.findById(req.params.id)
      .populate('clientId')
      .populate('userId', 'name email exportLogo');
    if (!project) return res.status(404).json({ error: 'Not found' });

    let items = await Item.find({ projectId: req.params.id, deleted: { $ne: true } }).sort({ seq: 1 });

    // Apply filters if provided
    if (req.body.contractorFilter) items = items.filter(i => i.contractor === req.body.contractorFilter);
    if (req.body.categoryFilter)   items = items.filter(i => i.category   === req.body.categoryFilter);
    if (req.body.statusFilter)     items = items.filter(i => i.status     === req.body.statusFilter);
    const plans = await Plan.find({ projectId: req.params.id }).sort({ order: 1, createdAt: 1 });

    // ── Helpers ──────────────────────────────────
    function base64ToBuffer(b64) {
      if (!b64) return null;
      try {
        const clean = b64.includes(',') ? b64.split(',')[1] : b64;
        return Buffer.from(clean, 'base64');
      } catch (e) { return null; }
    }

    // Status/priority colors — strictly 6 hex chars
    function statusBg(s) {
      if (s === 'closed') return 'D0EBDA';
      if (s === 'in_progress') return 'FFF3E0';
      return 'FDE8E8';
    }
    function statusFg(s) {
      if (s === 'closed') return '2D8653';
      if (s === 'in_progress') return 'C78A20';
      return 'D94141';
    }
    function priorityBg(p) {
      if (p === 'critical') return 'FDE8E8';
      if (p === 'high') return 'FDEEE0';
      if (p === 'low') return 'EFF6FF';
      return 'FFF3E0';
    }
    function priorityFg(p) {
      if (p === 'critical') return 'D94141';
      if (p === 'high') return 'E07B2A';
      if (p === 'low') return '3B82F6';
      return 'C78A20';
    }

    function caps(str) { return str ? str.toUpperCase() : ''; }
    function insRef(seq) { return `INS_${String(seq).padStart(3, '0')}`; }

    const projectName  = project.name  || 'Untitled Project';
    const projectRef   = project.ref   || 'No Ref';
    const projectDate  = project.date  || '';
    const inspectorName = project.userId?.name || '';
    const clientName   = project.clientId?.name || '';

    const visitLabel = project.visits?.length
      ? `Visit ${project.visits[project.visits.length - 1].visitNumber || project.visits.length} — ${project.visits[project.visits.length - 1].date || ''}`
      : '';

    // ── Header & Footer (shared) ─────────────────
    const makeHeader = () => new Header({
      children: [new Paragraph({
        border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: 'CCCCCC' } },
        spacing: { after: 80 },
        children: [
          new TextRun({ text: projectName, bold: true, size: 18, font: 'Calibri', color: '333333' }),
          new TextRun({ text: '    |    ', size: 18, color: 'CCCCCC' }),
          new TextRun({ text: visitLabel || projectDate, size: 18, font: 'Calibri', color: '666666' }),
          new TextRun({ text: '    |    ', size: 18, color: 'CCCCCC' }),
          new TextRun({ text: projectRef, size: 18, font: 'Calibri', color: '666666' }),
        ]
      })]
    });

    const makeFooter = () => new Footer({
      children: [new Paragraph({
        border: { top: { style: BorderStyle.SINGLE, size: 6, color: 'CCCCCC' } },
        spacing: { before: 80 },
        alignment: AlignmentType.RIGHT,
        children: [
          new TextRun({ text: 'Page ', size: 16, font: 'Calibri', color: '888888' }),
          new TextRun({ children: [PageNumber.CURRENT], size: 16, font: 'Calibri', color: '888888' }),
          new TextRun({ text: ' of ', size: 16, font: 'Calibri', color: '888888' }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, font: 'Calibri', color: '888888' }),
        ]
      })]
    });

    // ── PAGE 1: Cover ────────────────────────────
    const coverChildren = [];

    const wallpaperB64 = req.body.wallpaper || project.cover?.wallpaper;
    if (wallpaperB64) {
      const wBuf = base64ToBuffer(wallpaperB64);
      if (wBuf) {
        coverChildren.push(new Paragraph({
          children: [new ImageRun({ data: wBuf, transformation: { width: 594, height: 300 }, type: 'jpg' })],
          spacing: { after: 0 }
        }));
      }
    } else {
      coverChildren.push(new Paragraph({ text: '', spacing: { after: 2800 } }));
    }

    const logoB64 = req.body.logo || project.cover?.logo || project.userId?.exportLogo;
    if (logoB64) {
      const lBuf = base64ToBuffer(logoB64);
      if (lBuf) {
        coverChildren.push(new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new ImageRun({ data: lBuf, transformation: { width: 110, height: 55 }, type: 'png' })],
          spacing: { before: 400, after: 200 }
        }));
      }
    }

    coverChildren.push(new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 240, after: 100 },
      children: [new TextRun({ text: projectName.toUpperCase(), bold: true, size: 52, font: 'Calibri', color: '1A1A1A' })]
    }));

    coverChildren.push(new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 60 },
      children: [new TextRun({ text: 'INSPECTION REPORT', size: 26, font: 'Calibri', color: '666666' })]
    }));

    coverChildren.push(new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: 480 },
      children: [new TextRun({ text: '─────────────────────────────', color: 'DDDDDD', size: 18 })]
    }));

    const infoLines = [
      clientName    ? `Client: ${clientName}`       : null,
      projectRef    ? `Ref: ${projectRef}`           : null,
      projectDate   ? `Date: ${projectDate}`         : null,
      inspectorName ? `Inspector: ${inspectorName}` : null,
      `Total Items: ${items.length}`,
    ].filter(Boolean);

    coverChildren.push(new Paragraph({
      alignment: AlignmentType.RIGHT,
      spacing: { before: 600 },
      children: infoLines.flatMap((line, i) => [
        new TextRun({ text: line, size: 19, font: 'Calibri', color: '333333', break: i === 0 ? 0 : 1 })
      ])
    }));

    coverChildren.push(new Paragraph({ children: [new PageBreak()] }));

    // ── PAGE 2: Table of Contents ─────────────────
    const tocChildren = [
      new Paragraph({
        spacing: { before: 0, after: 240 },
        children: [new TextRun({ text: 'Table of Contents', bold: true, size: 36, font: 'Calibri', color: '1A1A1A' })]
      }),
      new TableOfContents('Table of Contents', {
        hyperlink: true,
        headingStyleRange: '1-3',
      }),
      new Paragraph({ children: [new PageBreak()] }),
    ];

    // ── PAGE 3: Executive Summary ─────────────────
    const summaryChildren = [];
    if (project.summary && project.summary.trim()) {
      summaryChildren.push(new Paragraph({
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 0, after: 160 },
        children: [new TextRun({ text: 'Executive Summary', bold: true, size: 34, font: 'Calibri' })]
      }));
      summaryChildren.push(new Paragraph({
        spacing: { after: 160 },
        children: [new TextRun({ text: project.summary, size: 22, font: 'Calibri', color: '333333' })]
      }));
    }
    if (project.appendix && project.appendix.trim()) {
      summaryChildren.push(new Paragraph({
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 320, after: 120 },
        children: [new TextRun({ text: 'Appendix / Notes', bold: true, size: 28, font: 'Calibri' })]
      }));
      summaryChildren.push(new Paragraph({
        spacing: { after: 160 },
        children: [new TextRun({ text: project.appendix, size: 22, font: 'Calibri', color: '333333' })]
      }));
    }
    if (summaryChildren.length > 0) {
      summaryChildren.push(new Paragraph({ children: [new PageBreak()] }));
    }

    // ── PAGE 4: Plans ─────────────────────────────
    const plansChildren = [];
    if (plans.length > 0) {
      plansChildren.push(new Paragraph({
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 0, after: 240 },
        children: [new TextRun({ text: 'Floor Plans', bold: true, size: 34, font: 'Calibri' })]
      }));

      for (const plan of plans) {
        if (plan.image) {
          const pBuf = base64ToBuffer(plan.image);
          if (pBuf) {
            plansChildren.push(new Paragraph({
              spacing: { before: 240, after: 80 },
              children: [new ImageRun({ data: pBuf, transformation: { width: 594, height: 400 }, type: 'jpg' })]
            }));
          }
        }
        plansChildren.push(new Paragraph({
          spacing: { before: 60, after: 40 },
          children: [new TextRun({ text: plan.name || 'Floor Plan', bold: true, size: 22, font: 'Calibri' })]
        }));
        if (plan.note && plan.note.trim()) {
          plansChildren.push(new Paragraph({
            spacing: { after: 200 },
            children: [new TextRun({ text: plan.note, size: 20, font: 'Calibri', color: '666666', italics: true })]
          }));
        }
      }
      plansChildren.push(new Paragraph({ children: [new PageBreak()] }));
    }

    // ── PAGE 5+: Inspection Items ─────────────────
    const itemsChildren = [];

    itemsChildren.push(new Paragraph({
      heading: HeadingLevel.HEADING_1,
      spacing: { before: 0, after: 320 },
      children: [new TextRun({ text: 'Observations & Findings', bold: true, size: 36, font: 'Calibri' })]
    }));

    // Helper: plain label+value line
    function metaLine(label, value) {
      return new Paragraph({
        spacing: { after: 50 },
        children: [
          new TextRun({ text: label + ':  ', bold: true, size: 18, font: 'Calibri', color: '888888' }),
          new TextRun({ text: value || '—', size: 18, font: 'Calibri', color: '222222' })
        ]
      });
    }

    for (const item of items) {
      const allPhotos = [item.photo, item.photoAfter, ...(item.photoExtras || [])].filter(Boolean);
      const hasPhoto = allPhotos.length > 0;
      const ref = insRef(item.seq);
      const statusLabel = (item.status || 'open').replace(/_/g, ' ');
      const priorityLabel = (item.priority || 'medium').charAt(0).toUpperCase() + (item.priority || 'medium').slice(1);

      // ── Details column content ──────────────────
      const detailsChildren = [
        // INS ref line
        new Paragraph({
          spacing: { before: 0, after: 80 },
          children: [new TextRun({ text: ref, bold: true, size: 22, font: 'Calibri', color: '2C2C2C' })]
        }),
        // Description bold
        new Paragraph({
          spacing: { before: 0, after: 160 },
          children: [new TextRun({ text: item.description || '', bold: true, size: 24, font: 'Calibri', color: '1A1A1A' })]
        }),
        // All fields as label: value
        metaLine('Status',      statusLabel.charAt(0).toUpperCase() + statusLabel.slice(1)),
        metaLine('Priority',    priorityLabel),
        metaLine('Category',    item.category   || '—'),
        metaLine('Location',    item.location   || '—'),
        metaLine('Contractor',  item.contractor || '—'),
        metaLine('Visit',       String(item.visitNumber || 1)),
        metaLine('Date',        item.date        || '—'),
      ];

      // Notes
      if (item.notes && item.notes.trim()) {
        detailsChildren.push(new Paragraph({
          spacing: { before: 120, after: 0 },
          children: [new TextRun({ text: 'Notes:  ' + item.notes, size: 17, font: 'Calibri', color: '888888', italics: true })]
        }));
      }

      let cardRow;
      if (hasPhoto) {
        const photoParas = allPhotos.map(function(p) {
          const buf = base64ToBuffer(p);
          if (!buf) return new Paragraph({ text: '' });
          return new Paragraph({
            spacing: { after: 80 },
            children: [new ImageRun({ data: buf, transformation: { width: 160, height: 160 }, type: 'jpg' })]
          });
        });

        cardRow = new TableRow({
          children: [
            // Photo column 35%
            new TableCell({
              width: { size: 35, type: WidthType.PERCENTAGE },
              verticalAlign: VerticalAlign.TOP,
              margins: { top: 100, bottom: 100, left: 0, right: 160 },
              children: photoParas
            }),
            // Details column 65%
            new TableCell({
              width: { size: 65, type: WidthType.PERCENTAGE },
              verticalAlign: VerticalAlign.TOP,
              margins: { top: 100, bottom: 100, left: 100, right: 0 },
              children: detailsChildren
            }),
          ]
        });
      } else {
        // No photo — full width details
        cardRow = new TableRow({
          children: [
            new TableCell({
              width: { size: 100, type: WidthType.PERCENTAGE },
              verticalAlign: VerticalAlign.TOP,
              margins: { top: 100, bottom: 100, left: 100, right: 100 },
              children: detailsChildren
            })
          ]
        });
      }

      // Card table (no outer border, just content)
      itemsChildren.push(new Table({
        layout: TableLayoutType.FIXED,
        width: { size: 100, type: WidthType.PERCENTAGE },
        borders: {
          top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE },
          left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE },
          insideH: { style: BorderStyle.NONE }, insideV: { style: BorderStyle.NONE }
        },
        rows: [cardRow]
      }));

      // Thin divider between items
      itemsChildren.push(new Paragraph({
        spacing: { before: 160, after: 160 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'E8E8E8' } },
        children: [new TextRun({ text: '' })]
      }));
    }

    // ── Assemble document ─────────────────────────
    const doc = new Document({
      features: { updateFields: true },
      styles: {
        paragraphStyles: [
          {
            id: 'Heading1', name: 'Heading 1',
            basedOn: 'Normal', next: 'Normal',
            run: { bold: true, size: 34, font: 'Calibri', color: '1A1A1A' },
            paragraph: { spacing: { before: 240, after: 120 } }
          },
          {
            id: 'Heading2', name: 'Heading 2',
            basedOn: 'Normal', next: 'Normal',
            run: { bold: true, size: 28, font: 'Calibri', color: '333333' },
            paragraph: { spacing: { before: 160, after: 80 } }
          },
        ]
      },
      sections: [
        // Cover — no header/footer
        {
          properties: {},
          children: coverChildren
        },
        // TOC + Summary + Plans + Items — with header/footer
        {
          properties: {},
          headers: { default: makeHeader() },
          footers: { default: makeFooter() },
          children: [
            ...tocChildren,
            ...summaryChildren,
            ...plansChildren,
            ...itemsChildren,
          ]
        }
      ]
    });

    const buffer = await Packer.toBuffer(doc);
    const safeName = projectName.replace(/[^a-z0-9]/gi, '_');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}_Inspection.docx"`);
    res.send(buffer);

  } catch (e) {
    console.error('Word export error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════
// AI SUMMARY
// ═══════════════════════════════════════════════

app.post('/api/ai/summary', auth, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'No prompt' });
    const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
    if (!ANTHROPIC_KEY) return res.status(500).json({ error: 'AI not configured' });
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = data.content?.[0]?.text;
    if (!text) return res.status(500).json({ error: 'AI returned no text' });
    res.json({ summary: text.trim() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════
// CRON — Auto-cleanup trash (24hr)
// ═══════════════════════════════════════════════

setInterval(async () => {
  try {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const result = await Item.deleteMany({ deleted: true, deletedAt: { $lt: cutoff } });
    if (result.deletedCount > 0) console.log(`🗑️ Auto-cleaned ${result.deletedCount} trashed items`);
  } catch (e) { console.error('Trash cleanup error:', e.message); }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════

app.listen(PORT, () => console.log(`🚀 MLA Inspection API v3.0 running on port ${PORT}`));
