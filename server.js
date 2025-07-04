// ===================================
//  1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ===================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const http = require('http'); // Usado para Socket.IO
const { Server } = require('socket.io'); // --> NUEVO: Importamos Server de socket.io

const app = express();
const port = process.env.PORT || 3001;

// Middlewares globales

app.use(express.json());

// Pool de Conexión a la Base de Datos
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// --> NUEVO: Creamos el servidor HTTP explícitamente
const server = http.createServer(app);

// --> NUEVO: Instanciamos Socket.IO y lo conectamos al servidor HTTP

const frontendURL = "http://localhost:5173"; // Puerto por defecto de Vite

// Configura CORS para Express
app.use(cors({ origin: frontendURL }));

// Configura CORS para Socket.IO
const io = new Server(server, {
    cors: {
        origin: frontendURL,
        methods: ["GET", "POST", "PATCH", "DELETE"]
    }
});


// ===================================
//  2. MIDDLEWARES DE AUTENTICACIÓN
// ===================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function isAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Acceso denegado. Se requiere rol de administrador." });
    }
    next();
}

// ===================================
//  3. ENDPOINTS DE AUTENTICACIÓN
// ===================================
// Registro de usuario
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email y contraseña son requeridos.' });

    try {
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);
        const newUser = await pool.query(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, role, is_approved, created_at",
            [email, password_hash]
        );
        
        const userData = newUser.rows[0];
        
        // --> NUEVO: Emitir evento de nuevo usuario registrado a todos los administradores
        io.emit('user:registered', {
            id: userData.id,
            email: userData.email,
            role: userData.role,
            created_at: userData.created_at
        });
        
        res.status(201).json({ message: "Usuario registrado. Pendiente de aprobación.", user: userData });
    } catch (error) {
        if (error.code === '23505') return res.status(400).json({ message: "El email ya está en uso." });
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

// Inicio de sesión de usuario
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email y contraseña son requeridos.' });

    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ message: "Credenciales inválidas." });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: "Credenciales inválidas." });
        
        if (!user.is_approved) return res.status(403).json({ message: "Tu cuenta está pendiente de aprobación." });

        const payload = { userId: user.id, role: user.role, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.json({ message: "Inicio de sesión exitoso", token, user: { id: user.id, email: user.email, role: user.role } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});
// ===================================
//  3.b ENDPOINTS DE USUARIOS (SOLO ADMIN)
// ===================================

// Obtener todos los usuarios pendientes de aprobación
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT id, email, role, created_at FROM users WHERE is_approved = FALSE");
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error al obtener usuarios pendientes" });
    }
});

// Aprobar un usuario por su ID
app.patch('/api/users/:id/approve', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query("UPDATE users SET is_approved = TRUE WHERE id = $1 RETURNING id, email, role, is_approved", [id]);
        if (result.rowCount === 0) return res.status(404).json({ message: "Usuario no encontrado" });
        
        const approvedUser = result.rows[0];
        
        // --> NUEVO: Emitir evento de usuario aprobado a todos los clientes conectados
        io.emit('user:approved', {
            userId: approvedUser.id,
            email: approvedUser.email,
            role: approvedUser.role
        });
        
        res.json({ message: "Usuario aprobado correctamente", user: approvedUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error al aprobar usuario" });
    }
});

// ===================================
//  4. ENDPOINTS DE LA APLICACIÓN (LOTES Y VENTAS)
// ===================================
// Obtener todos los lotes con sus ventas
app.get('/api/batches', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT
                b.id as batch_id, b.bread_type, b.quantity_made, b.price, b.date, b.created_by,
                u.email as created_by_email,
                s.id as sale_id, s.person_name, s.quantity_sold, s.is_paid, s.is_delivered, s.created_at
            FROM bread_batches b
            LEFT JOIN sales s ON b.id = s.batch_id
            LEFT JOIN users u ON b.created_by = u.id
            ORDER BY b.date DESC, b.id DESC, s.created_at ASC;
        `;
        const { rows } = await pool.query(query);
        const batches = {};
        rows.forEach(row => {
            if (!batches[row.batch_id]) {
                batches[row.batch_id] = {
                    id: row.batch_id,
                    breadType: row.bread_type,
                    quantityMade: row.quantity_made,
                    price: row.price,
                    date: row.date,
                    createdBy: row.created_by_email, // Enviamos el email para mostrar en el frontend
                    sales: []
                };
            }
            if (row.sale_id) {
                batches[row.batch_id].sales.push({
                    id: row.sale_id,
                    personName: row.person_name,
                    quantitySold: row.quantity_sold,
                    isPaid: row.is_paid,
                    isDelivered: row.is_delivered,
                    createdAt: row.created_at
                });
            }
        });
        res.json(Object.values(batches));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Crear un nuevo lote de pan
app.post('/api/batches', authenticateToken, async (req, res) => {
    const { breadType, quantityMade, price } = req.body;
    const createdBy = req.user.userId;

    try {
        // Obtenemos también el email del usuario para emitirlo en el evento
        const query = `
            WITH new_batch AS (
                INSERT INTO bread_batches (bread_type, quantity_made, price, created_by) 
                VALUES ($1, $2, $3, $4) 
                RETURNING *
            )
            SELECT nb.*, u.email as created_by_email FROM new_batch nb
            JOIN users u ON nb.created_by = u.id;
        `;
        const { rows } = await pool.query(query, [breadType, quantityMade, price, createdBy]);
        
        const newBatchData = rows[0];
        const newBatch = {
            id: newBatchData.id,
            breadType: newBatchData.bread_type,
            quantityMade: newBatchData.quantity_made,
            price: newBatchData.price,
            date: newBatchData.date,
            createdBy: newBatchData.created_by_email, // Usamos el email
            sales: []
        };
        
        // --> NUEVO: Emitir evento de nuevo lote a todos los clientes
        io.emit('batch:created', newBatch);

        res.status(201).json(newBatch);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Eliminar un lote (solo admins)
app.delete('/api/batches/:batchId', authenticateToken, isAdmin, async (req, res) => {
    const { batchId } = req.params;
    try {
        // Gracias a "ON DELETE CASCADE" en la tabla 'sales', no necesitamos borrar las ventas manualmente.
        await pool.query('DELETE FROM bread_batches WHERE id = $1', [batchId]);

        // --> NUEVO: Emitir evento de lote eliminado a todos los clientes
        io.emit('batch:deleted', parseInt(batchId));

        res.status(200).json({ message: 'Lote eliminado correctamente', batchId: parseInt(batchId) });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Añadir una nueva venta a un lote
app.post('/api/batches/:batchId/sales', authenticateToken, async (req, res) => {
    const { batchId } = req.params;
    const { personName, quantitySold } = req.body;
    const createdBy = req.user.userId;
    try {
        const { rows } = await pool.query(
            'INSERT INTO sales (batch_id, person_name, quantity_sold, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
            [batchId, personName, quantitySold, createdBy]
        );

        const newSale = rows[0];

        // --> NUEVO: Emitir evento de nueva venta a todos los clientes
        io.emit('sale:created', {
            batchId: newSale.batch_id,
            sale: { // Formateamos para que coincida con la estructura del frontend
                id: newSale.id,
                personName: newSale.person_name,
                quantitySold: newSale.quantity_sold,
                isPaid: newSale.is_paid,
                isDelivered: newSale.is_delivered,
                createdAt: newSale.created_at
            }
        });

        res.status(201).json(newSale); // La respuesta a la petición original sigue siendo la misma
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Actualizar una venta (pagado/entregado)
app.patch('/api/batches/:batchId/sales/:saleId', authenticateToken, async (req, res) => {
    const { saleId } = req.params;
    const { isPaid, isDelivered } = req.body;

    // Restricción para que solo admins puedan marcar como pagado
    if (typeof isPaid !== 'undefined' && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Solo los administradores pueden cambiar el estado de pago.' });
    }

    try {
        const fields = [], values = [];
        let queryIndex = 1;

        if (typeof isPaid !== 'undefined') { fields.push(`is_paid = $${queryIndex++}`); values.push(isPaid); }
        if (typeof isDelivered !== 'undefined') { fields.push(`is_delivered = $${queryIndex++}`); values.push(isDelivered); }
        
        if (fields.length === 0) return res.status(400).json({ message: 'No hay campos para actualizar.' });
        
        values.push(saleId);
        const query = `UPDATE sales SET ${fields.join(', ')} WHERE id = $${queryIndex} RETURNING *`;
        const { rows } = await pool.query(query, values);
        
        const updatedSale = rows[0];

        // --> NUEVO: Emitir evento de venta actualizada a todos los clientes
        io.emit('sale:updated', {
            batchId: updatedSale.batch_id,
            sale: { // Formateamos para que coincida con la estructura del frontend
                id: updatedSale.id,
                personName: updatedSale.person_name,
                quantitySold: updatedSale.quantity_sold,
                isPaid: updatedSale.is_paid,
                isDelivered: updatedSale.is_delivered,
                createdAt: updatedSale.created_at
            }
        });

        res.json(updatedSale);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Eliminar una venta específica
app.delete('/api/batches/:batchId/sales/:saleId', authenticateToken, async (req, res) => {
    const { batchId, saleId } = req.params;
    
    try {
        // Verificar que la venta existe y pertenece al lote especificado
        const checkQuery = 'SELECT * FROM sales WHERE id = $1 AND batch_id = $2';
        const checkResult = await pool.query(checkQuery, [saleId, batchId]);
        
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ message: 'Venta no encontrada' });
        }
        
        // Eliminar la venta
        await pool.query('DELETE FROM sales WHERE id = $1', [saleId]);
        
        // Emitir evento de venta eliminada a todos los clientes
        io.emit('sale:deleted', {
            batchId: parseInt(batchId),
            saleId: parseInt(saleId)
        });
        
        res.status(200).json({ 
            message: 'Venta eliminada correctamente', 
            batchId: parseInt(batchId),
            saleId: parseInt(saleId)
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// ===================================
//  5. GESTIÓN DE CONEXIONES SOCKET.IO
// ===================================

io.on('connection', (socket) => {
    console.log(`🔌 Nuevo cliente conectado: ${socket.id}`);

    socket.on('disconnect', () => {
        console.log(`🔌 Cliente desconectado: ${socket.id}`);
    });
});

// ===================================
//  6. INICIO DEL SERVIDOR
// ===================================

// --> MODIFICADO: Usamos 'server.listen' en lugar de 'app.listen'
server.listen(port, () => {
    console.log(`🚀 Servidor backend corriendo en http://localhost:${port}`);
    console.log(`📡 Socket.IO escuchando para conexiones en tiempo real.`);
});