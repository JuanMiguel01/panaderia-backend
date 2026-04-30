// server.js — Versión con presets de pan y mejoras

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');
const http     = require('http');
const { Server } = require('socket.io');

const app  = express();
const port = process.env.PORT || 3001;

// ===================================
//  DB
// ===================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => console.error('Unexpected DB error', err));

// ── Auto-create bread_presets table + seed defaults ───────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bread_presets (
      id         SERIAL PRIMARY KEY,
      name       VARCHAR(100) NOT NULL UNIQUE,
      price      DECIMAL(10,2) NOT NULL,
      emoji      VARCHAR(10) DEFAULT '🍞',
      is_active  BOOLEAN DEFAULT TRUE,
      sort_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Seed default presets only if table is empty
  const { rows } = await pool.query('SELECT COUNT(*) FROM bread_presets');
  if (parseInt(rows[0].count) === 0) {
    const defaults = [
      { name: 'Pan Bola',        price: 200, emoji: '🫓', sort: 1 },
      { name: 'Pan Perro',       price: 200, emoji: '🌭', sort: 2 },
      { name: 'Hamburguesa',     price: 285, emoji: '🍔', sort: 3 },
      { name: 'Tostadas',        price: 130, emoji: '🍞', sort: 4 },
      { name: 'Pan Bola 90g',    price: 350, emoji: '🫓', sort: 5 },
      { name: 'Base de Pizzas',  price: 290, emoji: '🍕', sort: 6 },
      { name: 'Pan Perro Chico', price: 120, emoji: '🌭', sort: 7 },
      { name: 'Pan Molde',       price: 310, emoji: '🍞', sort: 8 },
      { name: 'Pan Hambur',      price: 290, emoji: '🍔', sort: 9 },
      { name: 'Pan Flauta',      price: 140, emoji: '🥖', sort: 10 },
    ];
    for (const d of defaults) {
      await pool.query(
        'INSERT INTO bread_presets (name, price, emoji, sort_order) VALUES ($1, $2, $3, $4)',
        [d.name, d.price, d.emoji, d.sort]
      );
    }
    console.log('✅ Presets de pan sembrados por defecto');
  }

  // ── Financial schema migrations (safe: IF NOT EXISTS / ADD COLUMN IF NOT EXISTS) ──
  await pool.query(`ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS unit_cost DECIMAL(10,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE inventory_logs  ADD COLUMN IF NOT EXISTS unit_cost DECIMAL(10,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE inventory_logs  ADD COLUMN IF NOT EXISTS log_type  VARCHAR(20) DEFAULT 'adjust'`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cuadre_gastos (
      id         SERIAL PRIMARY KEY,
      date       DATE NOT NULL,
      category   VARCHAR(20) NOT NULL,
      concepto   VARCHAR(200) NOT NULL DEFAULT '',
      monto      DECIMAL(10,2) NOT NULL DEFAULT 0,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS partner_funds (
      id         SERIAL PRIMARY KEY,
      persona    VARCHAR(20) NOT NULL UNIQUE,
      saldo      DECIMAL(10,2) NOT NULL DEFAULT 0,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  const { rows: pfRows } = await pool.query('SELECT COUNT(*) FROM partner_funds');
  if (parseInt(pfRows[0].count) === 0) {
    for (const p of ['jm', 'michel', 'nadiel'])
      await pool.query('INSERT INTO partner_funds (persona) VALUES ($1)', [p]);
    console.log('✅ Fondos de socios creados');
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS partner_fund_movements (
      id                  SERIAL PRIMARY KEY,
      date                DATE NOT NULL,
      persona             VARCHAR(20) NOT NULL,
      ventas_parte        DECIMAL(10,2) NOT NULL DEFAULT 0,
      gastos_individuales DECIMAL(10,2) NOT NULL DEFAULT 0,
      utilidad_final      DECIMAL(10,2) NOT NULL DEFAULT 0,
      created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(date, persona)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS debts (
      id         SERIAL PRIMARY KEY,
      tipo       VARCHAR(10) NOT NULL CHECK (tipo IN ('cobrar','pagar')),
      concepto   VARCHAR(200) NOT NULL,
      persona    VARCHAR(100) DEFAULT '',
      monto      DECIMAL(10,2) NOT NULL DEFAULT 0,
      is_paid    BOOLEAN DEFAULT FALSE,
      date       DATE DEFAULT CURRENT_DATE,
      notes      VARCHAR(500) DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

initDB().catch(err => console.error('initDB error:', err));

// ===================================
//  HTTP + Socket.IO
// ===================================
const server = http.createServer(app);

const FRONTEND_URL = process.env.NODE_ENV === 'production'
  ? process.env.FRONTEND_URL
  : 'http://localhost:5173';

const io = new Server(server, {
  cors: { origin: FRONTEND_URL, methods: ['GET','POST','PATCH','DELETE','PUT'], credentials: true },
  pingTimeout: 60000,
});

// ===================================
//  MIDDLEWARES
// ===================================
app.use(express.json({ limit: '10mb' }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

if (process.env.NODE_ENV !== 'production') {
  app.use((req, _, next) => { console.log(`${req.method} ${req.path}`); next(); });
}

// ===================================
//  VALIDATION HELPERS
// ===================================
const validate = {
  email:       (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e),
  positiveInt: (n) => Number.isInteger(Number(n)) && Number(n) > 0,
  positiveNum: (n) => !isNaN(Number(n)) && Number(n) >= 0,
  string:      (s, maxLen = 200) => typeof s === 'string' && s.trim().length > 0 && s.length <= maxLen,
  date: (d) => {
    if (!d) return false;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
    return !isNaN(Date.parse(d));
  },
};

function bad(res, msg, status = 400) { return res.status(status).json({ message: msg }); }

// ===================================
//  AUTH MIDDLEWARE
// ===================================
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.sendStatus(403); }
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin')
    return bad(res, 'Acceso denegado. Se requiere rol de administrador.', 403);
  next();
}

function getDefaultPermissions(role) {
  switch (role) {
    case 'admin':   return { canViewStockCard:true,  canManageStock:true,  canViewAllSales:true,  canDeleteSales:true  };
    case 'manager': return { canViewStockCard:true,  canManageStock:true,  canViewAllSales:true,  canDeleteSales:false };
    default:        return { canViewStockCard:false, canManageStock:false, canViewAllSales:false, canDeleteSales:false };
  }
}

// ===================================
//  HEALTH CHECK
// ===================================
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'OK', db: 'connected', env: process.env.NODE_ENV || 'development', ts: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: 'ERROR', db: 'disconnected' });
  }
});

app.get('/', (_, res) => res.json({ message: 'Panadería API v2.1 ✓', docs: '/health' }));

// ===================================
//  AUTH ENDPOINTS
// ===================================
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!validate.email(email))         return bad(res, 'Email inválido.');
  if (!validate.string(password, 72)) return bad(res, 'Contraseña inválida (máx 72 chars).');
  if (password.length < 6)            return bad(res, 'La contraseña debe tener al menos 6 caracteres.');
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id,email,role,is_approved,created_at',
      [email.toLowerCase().trim(), hash]
    );
    io.emit('user:registered', { id: rows[0].id, email: rows[0].email });
    res.status(201).json({ message: 'Usuario registrado. Pendiente de aprobación.', user: rows[0] });
  } catch (err) {
    if (err.code === '23505') return bad(res, 'El email ya está en uso.');
    console.error('Register error:', err);
    res.status(500).json({ message: 'Error interno.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return bad(res, 'Email y contraseña son requeridos.');
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return bad(res, 'Credenciales inválidas.', 401);
    if (!user.is_approved)
      return bad(res, 'Tu cuenta está pendiente de aprobación.', 403);
    const permissions = user.permissions || getDefaultPermissions(user.role);
    const payload = { userId: user.id, role: user.role, email: user.email, permissions };
    const token   = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Inicio de sesión exitoso', token, user: { id: user.id, email: user.email, role: user.role, permissions } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Error interno.' });
  }
});

// ===================================
//  USERS (ADMIN)
// ===================================
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id,email,role,created_at FROM users WHERE is_approved=FALSE ORDER BY created_at DESC');
  res.json(rows);
});

app.get('/api/users/active', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,email,role,permissions,created_at FROM users WHERE is_approved=TRUE ORDER BY created_at DESC');
    res.json(rows.map(u => ({ ...u, permissions: u.permissions || getDefaultPermissions(u.role) })));
  } catch {
    const { rows } = await pool.query('SELECT id,email,role,created_at FROM users WHERE is_approved=TRUE ORDER BY created_at DESC');
    res.json(rows.map(u => ({ ...u, permissions: getDefaultPermissions(u.role) })));
  }
});

app.patch('/api/users/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rows, rowCount } = await pool.query('UPDATE users SET is_approved=TRUE WHERE id=$1 AND is_approved=FALSE RETURNING id,email,role', [id]);
  if (rowCount === 0) return bad(res, 'Usuario no encontrado o ya aprobado.', 404);
  io.emit('user:approved', rows[0]);
  res.json({ message: 'Usuario aprobado.', user: rows[0] });
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  if (id === req.user.userId) return bad(res, 'No puedes eliminar tu propia cuenta.');
  const { rowCount, rows } = await pool.query('DELETE FROM users WHERE id=$1 RETURNING id,email', [id]);
  if (rowCount === 0) return bad(res, 'Usuario no encontrado.', 404);
  res.json({ message: 'Usuario eliminado.', user: rows[0] });
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  const { email, password, role, permissions } = req.body;
  if (!validate.email(email))                          return bad(res, 'Email inválido.');
  if (!validate.string(password, 72) || password.length < 6) return bad(res, 'Contraseña inválida (mín. 6 chars).');
  if (!['admin','manager','employee'].includes(role))  return bad(res, 'Rol inválido.');
  try {
    const hash  = await bcrypt.hash(password, 12);
    const perms = permissions || getDefaultPermissions(role);
    const { rows } = await pool.query(
      'INSERT INTO users (email,password_hash,role,permissions,is_approved) VALUES ($1,$2,$3,$4,TRUE) RETURNING id,email,role,permissions,created_at',
      [email.toLowerCase().trim(), hash, role, perms]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return bad(res, 'El email ya está en uso.');
    console.error('Create user error:', err);
    res.status(500).json({ message: 'Error interno.' });
  }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { role, permissions } = req.body;
  if (!['admin','manager','employee'].includes(role)) return bad(res, 'Rol inválido.');
  const perms = permissions || getDefaultPermissions(role);
  const { rows, rowCount } = await pool.query(
    'UPDATE users SET role=$1,permissions=$2,updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND is_approved=TRUE RETURNING id,email,role,permissions',
    [role, perms, id]
  );
  if (rowCount === 0) return bad(res, 'Usuario no encontrado.', 404);
  res.json(rows[0]);
});

// ===================================
//  BATCHES
// ===================================
app.get('/api/batches', authenticateToken, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT b.id AS batch_id, b.bread_type, b.quantity_made, b.price, b.date, b.created_by,
           u.email AS created_by_email,
           s.id AS sale_id, s.person_name, s.quantity_sold, s.is_paid, s.is_delivered, s.is_gift, s.created_at
    FROM bread_batches b
    LEFT JOIN sales s ON b.id=s.batch_id
    LEFT JOIN users u ON b.created_by=u.id
    ORDER BY b.date DESC, b.id DESC, s.created_at ASC
  `);
  const batches = {};
  for (const row of rows) {
    if (!batches[row.batch_id]) {
      batches[row.batch_id] = {
        id: row.batch_id, breadType: row.bread_type,
        quantityMade: row.quantity_made, price: row.price,
        date: row.date, createdBy: row.created_by_email, sales: []
      };
    }
    if (row.sale_id) {
      batches[row.batch_id].sales.push({
        id: row.sale_id, personName: row.person_name,
        quantitySold: row.quantity_sold, isPaid: row.is_paid,
        isDelivered: row.is_delivered, isGift: row.is_gift, createdAt: row.created_at
      });
    }
  }
  res.json(Object.values(batches));
});

app.post('/api/batches', authenticateToken, async (req, res) => {
  const { breadType, quantityMade, price, date } = req.body;
  if (!validate.string(breadType))         return bad(res, 'Tipo de pan inválido.');
  if (!validate.positiveInt(quantityMade)) return bad(res, 'Cantidad inválida.');
  if (!validate.positiveNum(price))        return bad(res, 'Precio inválido.');
  const usarFecha = date !== undefined && date !== null && date !== '';
  if (usarFecha && !validate.date(date))   return bad(res, 'La fecha proporcionada no es válida (usa formato YYYY-MM-DD).');
  try {
    const query = usarFecha
      ? `WITH nb AS (INSERT INTO bread_batches (bread_type,quantity_made,price,created_by,date) VALUES ($1,$2,$3,$4,$5) RETURNING *)
         SELECT nb.*, u.email AS created_by_email FROM nb JOIN users u ON nb.created_by=u.id`
      : `WITH nb AS (INSERT INTO bread_batches (bread_type,quantity_made,price,created_by) VALUES ($1,$2,$3,$4) RETURNING *)
         SELECT nb.*, u.email AS created_by_email FROM nb JOIN users u ON nb.created_by=u.id`;
    const params = usarFecha
      ? [breadType.trim(), Number(quantityMade), Number(price), req.user.userId, date]
      : [breadType.trim(), Number(quantityMade), Number(price), req.user.userId];
    const { rows } = await pool.query(query, params);
    const b = rows[0];
    const batch = { id: b.id, breadType: b.bread_type, quantityMade: b.quantity_made, price: b.price, date: b.date, createdBy: b.created_by_email, sales: [] };
    io.emit('batch:created', batch);
    res.status(201).json(batch);
  } catch (err) {
    console.error('Create batch error:', err);
    res.status(500).json({ message: 'Error interno al crear el lote.' });
  }
});

app.delete('/api/batches/:batchId', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.batchId);
  if (isNaN(id)) return bad(res, 'ID inválido');
  await pool.query('DELETE FROM bread_batches WHERE id=$1', [id]);
  io.emit('batch:deleted', id);
  res.json({ message: 'Lote eliminado.', batchId: id });
});

app.patch('/api/batches/:batchId/date', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.batchId);
  const { date } = req.body;
  if (isNaN(id))            return bad(res, 'ID inválido');
  if (!validate.date(date)) return bad(res, 'Fecha inválida.');
  const { rows, rowCount } = await pool.query('UPDATE bread_batches SET date=$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2 RETURNING *', [date, id]);
  if (rowCount === 0) return bad(res, 'Lote no encontrado.', 404);
  io.emit('batch:updated', { batchId: id, updatedData: { date: rows[0].date } });
  res.json(rows[0]);
});

// ===================================
//  SALES
// ===================================
app.post('/api/batches/:batchId/sales', authenticateToken, async (req, res) => {
  const batchId = parseInt(req.params.batchId);
  const { personName, quantitySold, isGift } = req.body;
  if (isNaN(batchId))                      return bad(res, 'Batch ID inválido');
  if (!validate.string(personName, 100))   return bad(res, 'Nombre inválido.');
  if (!validate.positiveInt(quantitySold)) return bad(res, 'Cantidad inválida.');

  // Server-side stock validation
  const { rows: batchRows } = await pool.query('SELECT quantity_made FROM bread_batches WHERE id=$1', [batchId]);
  if (!batchRows[0]) return bad(res, 'Lote no encontrado.', 404);
  const { rows: soldRows } = await pool.query('SELECT COALESCE(SUM(quantity_sold),0) AS total FROM sales WHERE batch_id=$1', [batchId]);
  const remaining = batchRows[0].quantity_made - parseInt(soldRows[0].total);
  if (quantitySold > remaining)
    return bad(res, `Solo quedan ${remaining} unidades disponibles en este lote.`);

  const { rows } = await pool.query(
    'INSERT INTO sales (batch_id,person_name,quantity_sold,created_by,is_gift) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [batchId, personName.trim(), quantitySold, req.user.userId, !!isGift]
  );
  const s = rows[0];
  io.emit('sale:created', { batchId: s.batch_id, sale: { id:s.id, personName:s.person_name, quantitySold:s.quantity_sold, isPaid:s.is_paid, isDelivered:s.is_delivered, isGift:s.is_gift, createdAt:s.created_at } });
  res.status(201).json(s);
});

app.patch('/api/batches/:batchId/sales/:saleId', authenticateToken, async (req, res) => {
  const saleId = parseInt(req.params.saleId);
  const { isPaid, isDelivered } = req.body;
  if (isNaN(saleId)) return bad(res, 'Sale ID inválido');
  if (typeof isPaid !== 'undefined' && req.user.role !== 'admin')
    return bad(res, 'Solo administradores pueden cambiar el estado de pago.', 403);
  const fields = [], values = [];
  let i = 1;
  if (typeof isPaid      !== 'undefined') { fields.push(`is_paid=$${i++}`);      values.push(isPaid); }
  if (typeof isDelivered !== 'undefined') { fields.push(`is_delivered=$${i++}`); values.push(isDelivered); }
  if (!fields.length) return bad(res, 'Sin campos para actualizar.');
  values.push(saleId);
  const { rows } = await pool.query(`UPDATE sales SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, values);
  const s = rows[0];
  io.emit('sale:updated', { batchId: s.batch_id, sale: { id:s.id, personName:s.person_name, quantitySold:s.quantity_sold, isPaid:s.is_paid, isDelivered:s.is_delivered, createdAt:s.created_at } });
  res.json(s);
});

app.delete('/api/batches/:batchId/sales/:saleId', authenticateToken, isAdmin, async (req, res) => {
  const batchId = parseInt(req.params.batchId), saleId = parseInt(req.params.saleId);
  if (isNaN(batchId) || isNaN(saleId)) return bad(res, 'IDs inválidos');
  const { rowCount } = await pool.query('DELETE FROM sales WHERE id=$1 AND batch_id=$2', [saleId, batchId]);
  if (rowCount === 0) return bad(res, 'Venta no encontrada.', 404);
  io.emit('sale:deleted', { batchId, saleId });
  res.json({ message: 'Venta eliminada.', batchId, saleId });
});

// ===================================
//  BREAD PRESETS
// ===================================
// GET — any authenticated user (used in batch form)
app.get('/api/presets', authenticateToken, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM bread_presets WHERE is_active=TRUE ORDER BY sort_order ASC, name ASC');
  res.json(rows);
});

// POST — admin only
app.post('/api/presets', authenticateToken, isAdmin, async (req, res) => {
  const { name, price, emoji } = req.body;
  if (!validate.string(name, 100))     return bad(res, 'Nombre inválido.');
  if (!validate.positiveNum(price) || Number(price) === 0) return bad(res, 'Precio inválido.');
  const safeEmoji = (typeof emoji === 'string' && emoji.trim()) ? emoji.trim() : '🍞';
  try {
    const { rows } = await pool.query(
      'INSERT INTO bread_presets (name, price, emoji) VALUES ($1, $2, $3) RETURNING *',
      [name.trim(), Number(price), safeEmoji]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return bad(res, 'Ya existe un preset con ese nombre.');
    console.error('Create preset error:', err);
    res.status(500).json({ message: 'Error interno.' });
  }
});

// PUT — admin only
app.put('/api/presets/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { name, price, emoji } = req.body;
  if (!validate.string(name, 100))     return bad(res, 'Nombre inválido.');
  if (!validate.positiveNum(price) || Number(price) === 0) return bad(res, 'Precio inválido.');
  const safeEmoji = (typeof emoji === 'string' && emoji.trim()) ? emoji.trim() : '🍞';
  try {
    const { rows, rowCount } = await pool.query(
      'UPDATE bread_presets SET name=$1, price=$2, emoji=$3, updated_at=CURRENT_TIMESTAMP WHERE id=$4 RETURNING *',
      [name.trim(), Number(price), safeEmoji, id]
    );
    if (rowCount === 0) return bad(res, 'Preset no encontrado.', 404);
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return bad(res, 'Ya existe un preset con ese nombre.');
    res.status(500).json({ message: 'Error interno.' });
  }
});

// DELETE — admin only
app.delete('/api/presets/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rowCount } = await pool.query('DELETE FROM bread_presets WHERE id=$1', [id]);
  if (rowCount === 0) return bad(res, 'Preset no encontrado.', 404);
  res.status(204).send();
});

// ===================================
//  INVENTORY
// ===================================
app.get('/api/inventory', authenticateToken, isAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM inventory_items ORDER BY name ASC');
  res.json(rows);
});

app.post('/api/inventory', authenticateToken, isAdmin, async (req, res) => {
  const { name, quantity, unit } = req.body;
  if (!validate.string(name, 100))     return bad(res, 'Nombre inválido.');
  if (!validate.positiveNum(quantity)) return bad(res, 'Cantidad inválida.');
  if (!validate.string(unit, 20))      return bad(res, 'Unidad inválida.');
  try {
    const { rows } = await pool.query('INSERT INTO inventory_items (name,quantity,unit) VALUES ($1,$2,$3) RETURNING *', [name.trim(), Number(quantity), unit.trim()]);
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return bad(res, 'El insumo ya existe.');
    res.status(500).json({ message: 'Error interno.' });
  }
});

app.patch('/api/inventory/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id), change = Number(req.body.change);
  const purchaseCost = req.body.unit_cost !== undefined ? Number(req.body.unit_cost) : null;
  if (isNaN(id) || isNaN(change) || change === 0) return bad(res, 'Datos inválidos.');
  if (purchaseCost !== null && (isNaN(purchaseCost) || purchaseCost < 0)) return bad(res, 'Costo unitario inválido.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [item] } = await client.query('SELECT quantity, unit_cost FROM inventory_items WHERE id=$1 FOR UPDATE', [id]);
    if (!item) { await client.query('ROLLBACK'); return bad(res, 'Insumo no encontrado.', 404); }
    const after     = Number(item.quantity) + change;
    const currCost  = Number(item.unit_cost) || 0;
    const currQty   = Number(item.quantity);
    // Weighted-average cost: only recalculate on purchase with explicit cost
    let newUnitCost = currCost;
    let logUnitCost = currCost;
    if (change > 0 && purchaseCost !== null) {
      newUnitCost = currQty <= 0
        ? purchaseCost
        : (currQty * currCost + change * purchaseCost) / (currQty + change);
      logUnitCost = purchaseCost;
    }
    const logType = change > 0 ? 'purchase' : 'consume';
    const { rows: [updated] } = await client.query(
      'UPDATE inventory_items SET quantity=$1, unit_cost=$2 WHERE id=$3 RETURNING *',
      [after, newUnitCost, id]
    );
    await client.query(
      'INSERT INTO inventory_logs (item_id,user_id,change_amount,quantity_before,quantity_after,unit_cost,log_type) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, req.user.userId, change, item.quantity, after, logUnitCost, logType]
    );
    await client.query('COMMIT');
    res.json(updated);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Inventory update error:', err);
    res.status(500).json({ message: 'Error al actualizar.' });
  } finally { client.release(); }
});

app.get('/api/inventory/:id/logs', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rows } = await pool.query(`
    SELECT l.*, u.email AS user_email FROM inventory_logs l
    JOIN users u ON l.user_id=u.id WHERE l.item_id=$1 ORDER BY l.created_at DESC LIMIT 100
  `, [id]);
  res.json(rows);
});

app.delete('/api/inventory/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rowCount } = await pool.query('DELETE FROM inventory_items WHERE id=$1', [id]);
  if (rowCount === 0) return bad(res, 'Insumo no encontrado.', 404);
  res.status(204).send();
});

// ===================================
//  INVENTORY — DAILY SUMMARY
// ===================================
// Must be before /:id routes to avoid 'daily' being parsed as an id
app.get('/api/inventory/daily/:date', authenticateToken, isAdmin, async (req, res) => {
  const { date } = req.params;
  if (!validate.date(date)) return bad(res, 'Fecha inválida.');
  const { rows } = await pool.query(`
    SELECT
      i.id, i.name, i.unit,
      i.quantity   AS current_qty,
      i.unit_cost,
      COALESCE(d.entrada,   0)                       AS entrada,
      COALESCE(d.salida,    0)                       AS salida,
      COALESCE(d.inicio,    i.quantity)              AS inicio,
      COALESCE(d.final_qty, i.quantity)              AS final_qty,
      COALESCE(d.salida, 0) * i.unit_cost            AS costo_salida
    FROM inventory_items i
    LEFT JOIN (
      SELECT
        l.item_id,
        SUM(CASE WHEN l.change_amount > 0 THEN l.change_amount ELSE 0 END)       AS entrada,
        ABS(SUM(CASE WHEN l.change_amount < 0 THEN l.change_amount ELSE 0 END))  AS salida,
        (SELECT l2.quantity_before FROM inventory_logs l2
         WHERE l2.item_id = l.item_id AND DATE(l2.created_at) = $1
         ORDER BY l2.created_at ASC  LIMIT 1) AS inicio,
        (SELECT l2.quantity_after  FROM inventory_logs l2
         WHERE l2.item_id = l.item_id AND DATE(l2.created_at) = $1
         ORDER BY l2.created_at DESC LIMIT 1) AS final_qty
      FROM inventory_logs l
      WHERE DATE(l.created_at) = $1
      GROUP BY l.item_id
    ) d ON i.id = d.item_id
    ORDER BY i.name ASC
  `, [date]);
  res.json(rows);
});

// ===================================
//  GASTOS DEL CUADRE
// ===================================
app.get('/api/gastos/:date', authenticateToken, isAdmin, async (req, res) => {
  const { date } = req.params;
  if (!validate.date(date)) return bad(res, 'Fecha inválida.');
  const { rows } = await pool.query(
    'SELECT * FROM cuadre_gastos WHERE date=$1 ORDER BY category, created_at ASC', [date]
  );
  res.json(rows);
});

app.post('/api/gastos', authenticateToken, isAdmin, async (req, res) => {
  const { date, category, concepto, monto } = req.body;
  if (!validate.date(date)) return bad(res, 'Fecha inválida.');
  if (!['generales','jm','michel','nadiel','fondo'].includes(category)) return bad(res, 'Categoría inválida.');
  if (isNaN(Number(monto)) || Number(monto) < 0) return bad(res, 'Monto inválido.');
  const { rows } = await pool.query(
    'INSERT INTO cuadre_gastos (date,category,concepto,monto,created_by) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [date, category, (concepto || '').trim(), Number(monto), req.user.userId]
  );
  res.status(201).json(rows[0]);
});

app.delete('/api/gastos/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rowCount } = await pool.query('DELETE FROM cuadre_gastos WHERE id=$1', [id]);
  if (rowCount === 0) return bad(res, 'Gasto no encontrado.', 404);
  res.status(204).send();
});

// ===================================
//  FONDOS DE SOCIOS
// ===================================
app.get('/api/fondos', authenticateToken, isAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM partner_funds ORDER BY persona ASC');
  res.json(rows);
});

// Manual adjustment of a partner's fund (e.g. to set initial balance)
app.patch('/api/fondos/:persona', authenticateToken, isAdmin, async (req, res) => {
  const { persona } = req.params;
  if (!['jm','michel','nadiel'].includes(persona)) return bad(res, 'Persona inválida.');
  const { saldo } = req.body;
  if (isNaN(Number(saldo))) return bad(res, 'Saldo inválido.');
  const { rows } = await pool.query(
    'UPDATE partner_funds SET saldo=$1, updated_at=CURRENT_TIMESTAMP WHERE persona=$2 RETURNING *',
    [Number(saldo), persona]
  );
  res.json(rows[0]);
});

// Daily closing: calculate and persist financial result for a date
app.post('/api/fondos/cierre/:date', authenticateToken, isAdmin, async (req, res) => {
  const { date } = req.params;
  if (!validate.date(date)) return bad(res, 'Fecha inválida.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Total ventas (excluding gifts)
    const { rows: [vRow] } = await client.query(`
      SELECT COALESCE(SUM(s.quantity_sold * b.price), 0) AS total
      FROM bread_batches b
      JOIN sales s ON b.id = s.batch_id
      WHERE b.date = $1 AND s.is_gift = FALSE
    `, [date]);
    const totalVentas = Number(vRow.total);

    // 2. Costo de insumos consumidos ese día (consume logs)
    const { rows: [cRow] } = await client.query(`
      SELECT COALESCE(SUM(ABS(l.change_amount) * l.unit_cost), 0) AS total
      FROM inventory_logs l
      WHERE DATE(l.created_at) = $1 AND l.change_amount < 0
    `, [date]);
    const totalCostoInsumos = Number(cRow.total);

    // 3. Gastos agrupados por categoría
    const { rows: gRows } = await client.query(
      'SELECT category, SUM(monto) AS total FROM cuadre_gastos WHERE date=$1 GROUP BY category', [date]
    );
    const gastos = Object.fromEntries(gRows.map(g => [g.category, Number(g.total)]));

    const gastosGenerales = gastos['generales'] || 0;
    const gastosFondo     = gastos['fondo']     || 0;

    // 4. P&L
    const utilidadBruta = totalVentas - totalCostoInsumos;
    const utilidadNeta  = utilidadBruta - gastosGenerales;
    const parteBase     = utilidadNeta / 3;

    // 5. Per-partner movement & fund update
    const partners = ['jm', 'michel', 'nadiel'];
    const movements = [];
    for (const persona of partners) {
      const gastosInd    = gastos[persona] || 0;
      const utilidadFinal = parteBase - gastosInd;
      await client.query(`
        INSERT INTO partner_fund_movements (date,persona,ventas_parte,gastos_individuales,utilidad_final)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (date,persona) DO UPDATE
          SET ventas_parte=$3, gastos_individuales=$4, utilidad_final=$5
      `, [date, persona, parteBase, gastosInd, utilidadFinal]);
      await client.query(
        'UPDATE partner_funds SET saldo = saldo + $1, updated_at = CURRENT_TIMESTAMP WHERE persona = $2',
        [utilidadFinal, persona]
      );
      movements.push({ persona, parteBase, gastosInd, utilidadFinal });
    }

    await client.query('COMMIT');

    const { rows: fondosRows } = await pool.query('SELECT * FROM partner_funds ORDER BY persona');
    res.json({ date, totalVentas, totalCostoInsumos, gastosGenerales, gastosFondo,
               utilidadBruta, utilidadNeta, parteBase, movements, fondos: fondosRows });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Cierre error:', err);
    res.status(500).json({ message: 'Error al procesar el cierre.' });
  } finally { client.release(); }
});

// ===================================
//  DEUDAS
// ===================================
app.get('/api/deudas', authenticateToken, isAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM debts ORDER BY is_paid ASC, date DESC, created_at DESC'
  );
  res.json(rows);
});

app.post('/api/deudas', authenticateToken, isAdmin, async (req, res) => {
  const { tipo, concepto, persona, monto, date, notes } = req.body;
  if (!['cobrar','pagar'].includes(tipo))      return bad(res, 'Tipo inválido. Usa "cobrar" o "pagar".');
  if (!validate.string(concepto, 200))         return bad(res, 'Concepto inválido.');
  if (isNaN(Number(monto)) || Number(monto) <= 0) return bad(res, 'Monto inválido.');
  const useDate = date && validate.date(date) ? date : new Date().toISOString().split('T')[0];
  const { rows } = await pool.query(
    'INSERT INTO debts (tipo,concepto,persona,monto,date,notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [tipo, concepto.trim(), (persona||'').trim(), Number(monto), useDate, (notes||'').trim()]
  );
  res.status(201).json(rows[0]);
});

app.patch('/api/deudas/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { is_paid, concepto, monto, notes } = req.body;
  const fields = [], values = [];
  let i = 1;
  if (typeof is_paid  !== 'undefined') { fields.push(`is_paid=$${i++}`);  values.push(!!is_paid); }
  if (concepto !== undefined)          { fields.push(`concepto=$${i++}`); values.push(concepto.trim()); }
  if (monto    !== undefined)          { fields.push(`monto=$${i++}`);    values.push(Number(monto)); }
  if (notes    !== undefined)          { fields.push(`notes=$${i++}`);    values.push(notes.trim()); }
  if (!fields.length) return bad(res, 'Sin campos para actualizar.');
  values.push(id);
  const { rows, rowCount } = await pool.query(`UPDATE debts SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, values);
  if (rowCount === 0) return bad(res, 'Deuda no encontrada.', 404);
  res.json(rows[0]);
});

app.delete('/api/deudas/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rowCount } = await pool.query('DELETE FROM debts WHERE id=$1', [id]);
  if (rowCount === 0) return bad(res, 'Deuda no encontrada.', 404);
  res.status(204).send();
});

// ===================================
//  SOCKET.IO
// ===================================
io.on('connection', socket => {
  console.log(`🔌 Socket connected: ${socket.id}`);
  socket.on('disconnect', () => console.log(`🔌 Socket disconnected: ${socket.id}`));
});

// ===================================
//  ERROR HANDLERS
// ===================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ message: process.env.NODE_ENV === 'production' ? 'Error interno del servidor.' : err.message });
});

app.use('*', (req, res) => res.status(404).json({ message: `Ruta '${req.originalUrl}' no encontrada.` }));

// ===================================
//  START
// ===================================
server.listen(port, '0.0.0.0', () => {
  console.log(`\n🚀 Panadería Backend v2.1`);
  console.log(`   Puerto: ${port}`);
  console.log(`   Entorno: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Frontend: ${FRONTEND_URL}\n`);
});