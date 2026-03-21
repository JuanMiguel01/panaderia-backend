// server.js — Versión mejorada con seguridad, validación y manejo de errores

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

// ===================================
//  HTTP + Socket.IO
// ===================================
const server = http.createServer(app);

const FRONTEND_URL = process.env.NODE_ENV === 'production'
  ? process.env.FRONTEND_URL
  : 'http://localhost:5173';

const io = new Server(server, {
  cors: { origin: FRONTEND_URL, methods: ['GET','POST','PATCH','DELETE'], credentials: true },
  pingTimeout: 60000,
});

// ===================================
//  MIDDLEWARES
// ===================================
app.use(express.json({ limit: '10mb' }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Request logger (only non-production)
if (process.env.NODE_ENV !== 'production') {
  app.use((req, _, next) => { console.log(`${req.method} ${req.path}`); next(); });
}

// ===================================
//  VALIDATION HELPERS
// ===================================
const validate = {
  email: (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e),
  positiveInt: (n) => Number.isInteger(Number(n)) && Number(n) > 0,
  positiveNum: (n) => !isNaN(Number(n)) && Number(n) >= 0,
  string: (s, maxLen = 200) => typeof s === 'string' && s.trim().length > 0 && s.length <= maxLen,
  date: (d) => {
    if (!d) return false;
    // Aceptar formato YYYY-MM-DD
    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(d)) return false;
    return !isNaN(Date.parse(d));
  },
};

function bad(res, msg, status = 400) {
  return res.status(status).json({ message: msg });
}

// ===================================
//  AUTH MIDDLEWARE
// ===================================
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.sendStatus(403);
  }
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin')
    return bad(res, 'Acceso denegado. Se requiere rol de administrador.', 403);
  next();
}

function getDefaultPermissions(role) {
  switch (role) {
    case 'admin':   return { canViewStockCard:true,  canManageStock:true,  canViewAllSales:true,  canDeleteSales:true };
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

app.get('/', (_, res) => res.json({ message: 'Panadería API v2.0 ✓', docs: '/health' }));

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

    res.json({
      message: 'Inicio de sesión exitoso',
      token,
      user: { id: user.id, email: user.email, role: user.role, permissions }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Error interno.' });
  }
});

// ===================================
//  USERS (ADMIN)
// ===================================
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,email,role,created_at FROM users WHERE is_approved=FALSE ORDER BY created_at DESC'
  );
  res.json(rows);
});

app.get('/api/users/active', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id,email,role,permissions,created_at FROM users WHERE is_approved=TRUE ORDER BY created_at DESC'
    );
    res.json(rows.map(u => ({ ...u, permissions: u.permissions || getDefaultPermissions(u.role) })));
  } catch {
    const { rows } = await pool.query('SELECT id,email,role,created_at FROM users WHERE is_approved=TRUE ORDER BY created_at DESC');
    res.json(rows.map(u => ({ ...u, permissions: getDefaultPermissions(u.role) })));
  }
});

app.patch('/api/users/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return bad(res, 'ID inválido');
  const { rows, rowCount } = await pool.query(
    'UPDATE users SET is_approved=TRUE WHERE id=$1 AND is_approved=FALSE RETURNING id,email,role', [id]
  );
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
  if (!validate.email(email))                         return bad(res, 'Email inválido.');
  if (!validate.string(password, 72) || password.length < 6) return bad(res, 'Contraseña inválida (mín. 6 chars).');
  if (!['admin','manager','employee'].includes(role)) return bad(res, 'Rol inválido.');

  try {
    const hash = await bcrypt.hash(password, 12);
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

// ── CAMBIO: acepta campo opcional "date" ──────────────────
app.post('/api/batches', authenticateToken, async (req, res) => {
  const { breadType, quantityMade, price, date } = req.body;

  if (!validate.string(breadType))         return bad(res, 'Tipo de pan inválido.');
  if (!validate.positiveInt(quantityMade)) return bad(res, 'Cantidad inválida.');
  if (!validate.positiveNum(price))        return bad(res, 'Precio inválido.');

  // Si se mandó fecha, validarla; si no se mandó, la BD usa DEFAULT CURRENT_DATE
  const usarFecha = date !== undefined && date !== null && date !== '';
  if (usarFecha && !validate.date(date)) return bad(res, 'La fecha proporcionada no es válida (usa formato YYYY-MM-DD).');

  try {
    const query = usarFecha
      ? `WITH nb AS (
           INSERT INTO bread_batches (bread_type, quantity_made, price, created_by, date)
           VALUES ($1, $2, $3, $4, $5) RETURNING *
         )
         SELECT nb.*, u.email AS created_by_email FROM nb JOIN users u ON nb.created_by=u.id`
      : `WITH nb AS (
           INSERT INTO bread_batches (bread_type, quantity_made, price, created_by)
           VALUES ($1, $2, $3, $4) RETURNING *
         )
         SELECT nb.*, u.email AS created_by_email FROM nb JOIN users u ON nb.created_by=u.id`;

    const params = usarFecha
      ? [breadType.trim(), Number(quantityMade), Number(price), req.user.userId, date]
      : [breadType.trim(), Number(quantityMade), Number(price), req.user.userId];

    const { rows } = await pool.query(query, params);
    const b = rows[0];
    const batch = {
      id: b.id, breadType: b.bread_type, quantityMade: b.quantity_made,
      price: b.price, date: b.date, createdBy: b.created_by_email, sales: []
    };
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
  const { rows, rowCount } = await pool.query(
    'UPDATE bread_batches SET date=$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2 RETURNING *', [date, id]
  );
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
  if (typeof isPaid !== 'undefined')      { fields.push(`is_paid=$${i++}`);      values.push(isPaid); }
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
    const { rows } = await pool.query(
      'INSERT INTO inventory_items (name,quantity,unit) VALUES ($1,$2,$3) RETURNING *',
      [name.trim(), Number(quantity), unit.trim()]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return bad(res, 'El insumo ya existe.');
    res.status(500).json({ message: 'Error interno.' });
  }
});

app.patch('/api/inventory/:id', authenticateToken, isAdmin, async (req, res) => {
  const id = parseInt(req.params.id), change = Number(req.body.change);
  if (isNaN(id) || isNaN(change) || change === 0) return bad(res, 'Datos inválidos.');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [item] } = await client.query('SELECT quantity FROM inventory_items WHERE id=$1 FOR UPDATE', [id]);
    if (!item) { await client.query('ROLLBACK'); return bad(res, 'Insumo no encontrado.', 404); }

    const after = Number(item.quantity) + change;
    const { rows: [updated] } = await client.query('UPDATE inventory_items SET quantity=$1 WHERE id=$2 RETURNING *', [after, id]);
    await client.query(
      'INSERT INTO inventory_logs (item_id,user_id,change_amount,quantity_before,quantity_after) VALUES ($1,$2,$3,$4,$5)',
      [id, req.user.userId, change, item.quantity, after]
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
  res.status(500).json({
    message: process.env.NODE_ENV === 'production' ? 'Error interno del servidor.' : err.message
  });
});

app.use('*', (req, res) => res.status(404).json({ message: `Ruta '${req.originalUrl}' no encontrada.` }));

// ===================================
//  START
// ===================================
server.listen(port, '0.0.0.0', () => {
  console.log(`\n🚀 Panadería Backend v2.0`);
  console.log(`   Puerto: ${port}`);
  console.log(`   Entorno: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Frontend: ${FRONTEND_URL}\n`);
});