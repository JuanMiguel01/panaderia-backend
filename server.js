// ===================================
//  1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ===================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const port = process.env.PORT || 3001;

// Configuración de la base de datos
const pool = new Pool({
    // Para producción, usa DATABASE_URL de Neon
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Crear servidor HTTP para Socket.IO
const server = http.createServer(app);

// Configuración de CORS adaptable a producción y desarrollo
const frontendURL = process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL 
    : "http://localhost:5173";

// Middlewares
app.use(express.json());
app.use(cors({ 
    origin: frontendURL,
    credentials: true
}));

// Configuración de Socket.IO
const io = new Server(server, {
    cors: {
        origin: frontendURL,
        methods: ["GET", "POST", "PATCH", "DELETE"],
        credentials: true
    }
});

// Health check endpoint (requerido para muchos servicios de hosting)
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Panadería API - Servidor funcionando correctamente',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
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
        
        // Emitir evento de nuevo usuario registrado a todos los administradores
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

        const payload = { userId: user.id, role: user.role, email: user.email, permissions: user.permissions || getDefaultPermissions(user.role) };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        // Devolvemos el usuario completo, incluyendo sus permisos
        const userResponse = {
            id: user.id,
            email: user.email,
            role: user.role,
            permissions: user.permissions || getDefaultPermissions(user.role) // Aseguramos que siempre haya permisos
        };

        res.json({ message: "Inicio de sesión exitoso", token, user: userResponse });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});


// ===================================
//  3.b ENDPOINTS DE USUARIOS (SOLO ADMIN)
// ===================================
// server.js
// Reemplaza las funciones relacionadas con usuarios en tu server.js

// ===================================
//  3.b ENDPOINTS DE USUARIOS (SOLO ADMIN) - VERSIÓN CORREGIDA
// ===================================
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, email, role, created_at FROM users WHERE is_approved = FALSE ORDER BY created_at DESC"
        );
        console.log('📋 Usuarios pendientes encontrados:', result.rows.length);
        res.json(result.rows);
    } catch (error) {
        console.error('Error en /api/users/pending:', error);
        res.status(500).json({ message: "Error al obtener usuarios pendientes" });
    }
});

// 2. Aprobar un usuario pendiente
app.patch('/api/users/:id/approve', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            "UPDATE users SET is_approved = TRUE WHERE id = $1 AND is_approved = FALSE RETURNING id, email, role, created_at",
            [parseInt(id)]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: "Usuario no encontrado o ya aprobado" });
        }

        const approvedUser = result.rows[0];

        // Emitir evento de usuario aprobado
        io.emit('user:approved', {
            id: approvedUser.id,
            email: approvedUser.email,
            role: approvedUser.role,
            created_at: approvedUser.created_at
        });

        console.log('✅ Usuario aprobado:', approvedUser.email);
        res.json({ message: "Usuario aprobado correctamente", user: approvedUser });
    } catch (error) {
        console.error('Error aprobando usuario:', error);
        res.status(500).json({ message: "Error al aprobar usuario" });
    }
});

// 3. Eliminar usuario (funciona tanto para pendientes como activos)
app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // Verificar que no sea el propio usuario
        if (parseInt(id) === req.user.userId) {
            return res.status(400).json({ message: "No puedes eliminar tu propia cuenta" });
        }

        const result = await pool.query(
            "DELETE FROM users WHERE id = $1 RETURNING id, email",
            [parseInt(id)]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: "Usuario no encontrado" });
        }

        const deletedUser = result.rows[0];
        console.log('🗑️ Usuario eliminado:', deletedUser.email);
        res.json({ message: "Usuario eliminado correctamente", user: deletedUser });
    } catch (error) {
        console.error('Error eliminando usuario:', error);
        res.status(500).json({ message: "Error al eliminar usuario" });
    }
});
// Obtener todos los usuarios ACTIVOS (con manejo de errores mejorado)
app.get('/api/users/active', authenticateToken, isAdmin, async (req, res) => {
    try {
        // Primero verificar si la columna permissions existe
        const result = await pool.query(`
            SELECT id, email, role, created_at,
                CASE 
                    WHEN column_name IS NOT NULL THEN permissions
                    ELSE '{}'::jsonb
                END as permissions
            FROM users u
            LEFT JOIN information_schema.columns c ON c.table_name = 'users' AND c.column_name = 'permissions'
            WHERE u.is_approved = TRUE 
            ORDER BY u.created_at DESC
        `);
        
        // Si la consulta anterior no funciona, usar una consulta más simple
        if (result.rows.length === 0) {
            const fallbackResult = await pool.query(
                "SELECT id, email, role, created_at FROM users WHERE is_approved = TRUE ORDER BY created_at DESC"
            );
            
            // Agregar permissions por defecto basado en el rol
            const usersWithPermissions = fallbackResult.rows.map(user => ({
                ...user,
                permissions: getDefaultPermissions(user.role)
            }));
            
            return res.json(usersWithPermissions);
        }
        
        res.json(result.rows);
    } catch (error) {
        console.error('Error en /api/users/active:', error);
        
        // Intentar consulta de respaldo sin permissions
        try {
            const fallbackResult = await pool.query(
                "SELECT id, email, role, created_at FROM users WHERE is_approved = TRUE ORDER BY created_at DESC"
            );
            
            const usersWithPermissions = fallbackResult.rows.map(user => ({
                ...user,
                permissions: getDefaultPermissions(user.role)
            }));
            
            res.json(usersWithPermissions);
        } catch (fallbackError) {
            console.error('Error en consulta de respaldo:', fallbackError);
            res.status(500).json({ message: "Error al obtener usuarios activos" });
        }
    }
});

// Función auxiliar para obtener permisos por defecto según el rol
function getDefaultPermissions(role) {
    switch (role) {
        case 'admin':
            return {
                canViewStockCard: true,
                canManageStock: true,
                canViewAllSales: true,
                canDeleteSales: true
            };
        case 'manager':
            return {
                canViewStockCard: true,
                canManageStock: true,
                canViewAllSales: true,
                canDeleteSales: false
            };
        default:
            return {
                canViewStockCard: false,
                canManageStock: false,
                canViewAllSales: false,
                canDeleteSales: false
            };
    }
}

// Crear un nuevo usuario (admin-only) - VERSIÓN CORREGIDA
app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const { email, password, role, permissions } = req.body;
    if (!email || !password || !role) {
        return res.status(400).json({ message: 'Email, contraseña y rol son requeridos.' });
    }
    
    try {
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);
        
        const defaultPermissions = permissions || getDefaultPermissions(role);
        
        // Verificar si la columna permissions existe
        let query, values;
        try {
            query = `INSERT INTO users (email, password_hash, role, permissions, is_approved) 
                     VALUES ($1, $2, $3, $4, TRUE) 
                     RETURNING id, email, role, is_approved, created_at, permissions`;
            values = [email, password_hash, role, defaultPermissions];
            
            const newUser = await pool.query(query, values);
            res.status(201).json(newUser.rows[0]);
        } catch (columnError) {
            // Si falla, es probable que la columna permissions no exista
            console.log('Columna permissions no existe, usando consulta sin permissions');
            query = `INSERT INTO users (email, password_hash, role, is_approved) 
                     VALUES ($1, $2, $3, TRUE) 
                     RETURNING id, email, role, is_approved, created_at`;
            values = [email, password_hash, role];
            
            const newUser = await pool.query(query, values);
            const userWithPermissions = {
                ...newUser.rows[0],
                permissions: defaultPermissions
            };
            res.status(201).json(userWithPermissions);
        }
    } catch (error) {
        if (error.code === '23505') {
            return res.status(400).json({ message: "El email ya está en uso." });
        }
        console.error('Error creando usuario:', error);
        res.status(500).json({ message: "Error interno del servidor al crear usuario." });
    }
});
app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { role, permissions } = req.body;

    if (!role) {
        return res.status(400).json({ message: 'El rol es requerido.' });
    }
    
    try {
        const finalPermissions = permissions || getDefaultPermissions(role);
        
        // CORRECCIÓN CLAVE: No usamos JSON.stringify. El driver de pg maneja objetos JS directamente para columnas JSONB.
        const query = `
            UPDATE users 
            SET role = $1, permissions = $2, updated_at = CURRENT_TIMESTAMP
            WHERE id = $3 AND is_approved = TRUE
            RETURNING id, email, role, permissions, created_at, updated_at
        `;
        
        const values = [role, finalPermissions, parseInt(id)];
        
        const result = await pool.query(query, values);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ message: "Usuario no encontrado o no activo" });
        }
        
        res.json(result.rows[0]);
        
    } catch (error) {
        console.error('💥 Error actualizando usuario:', error);
        res.status(500).json({ message: "Error al actualizar usuario" });
    }
});
// ===================================
//  4 a. ENDPOINTS DE LA APLICACIÓN (LOTES Y VENTAS)
// ===================================
// Obtener todos los lotes con sus ventas
// Obtener todos los lotes con sus ventas - MODIFICADO
app.get('/api/batches', authenticateToken, async (req, res) => {
    try {
        // Añadimos s.is_gift a la consulta
        const query = `
            SELECT
                b.id as batch_id, b.bread_type, b.quantity_made, b.price, b.date, b.created_by,
                u.email as created_by_email,
                s.id as sale_id, s.person_name, s.quantity_sold, s.is_paid, s.is_delivered, s.is_gift, s.created_at
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
                    createdBy: row.created_by_email,
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
                    isGift: row.is_gift, // Devolvemos el nuevo campo
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
            createdBy: newBatchData.created_by_email,
            sales: []
        };
        
        // Emitir evento de nuevo lote a todos los clientes
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
        await pool.query('DELETE FROM bread_batches WHERE id = $1', [batchId]);
        
        // Emitir evento de lote eliminado a todos los clientes
        io.emit('batch:deleted', parseInt(batchId));

        res.status(200).json({ message: 'Lote eliminado correctamente', batchId: parseInt(batchId) });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});
// Añadir una nueva venta a un lote - MODIFICADO
app.post('/api/batches/:batchId/sales', authenticateToken, async (req, res) => {
    const { batchId } = req.params;
    const { personName, quantitySold, isGift } = req.body; // Añadimos isGift
    const createdBy = req.user.userId;
    try {
        // Añadimos is_gift a la inserción
        const { rows } = await pool.query(
            'INSERT INTO sales (batch_id, person_name, quantity_sold, created_by, is_gift) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [batchId, personName, quantitySold, createdBy, !!isGift] // Usamos !!isGift para asegurar que sea booleano
        );

        const newSale = rows[0];

        // Emitir evento de nueva venta a todos los clientes
        io.emit('sale:created', {
            batchId: newSale.batch_id,
            sale: {
                id: newSale.id,
                personName: newSale.person_name,
                quantitySold: newSale.quantity_sold,
                isPaid: newSale.is_paid,
                isDelivered: newSale.is_delivered,
                isGift: newSale.is_gift, // Notificamos el nuevo campo
                createdAt: newSale.created_at
            }
        });

        res.status(201).json(newSale);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Actualizar una venta (pagado/entregado)
app.patch('/api/batches/:batchId/sales/:saleId', authenticateToken, async (req, res) => {
    const { saleId } = req.params;
    const { isPaid, isDelivered } = req.body;

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

        // Emitir evento de venta actualizada a todos los clientes
        io.emit('sale:updated', {
            batchId: updatedSale.batch_id,
            sale: {
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
app.delete('/api/batches/:batchId/sales/:saleId', authenticateToken, isAdmin, async (req, res) => {
    const { batchId, saleId } = req.params;
    
    try {
        const checkQuery = 'SELECT * FROM sales WHERE id = $1 AND batch_id = $2';
        const checkResult = await pool.query(checkQuery, [saleId, batchId]);
        
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ message: 'Venta no encontrada' });
        }
        
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
//  4.b ENDPOINTS DE INVENTARIO DE INSUMOS (NUEVO)
// ===================================

// Obtener todos los insumos del inventario
app.get('/api/inventory', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM inventory_items ORDER BY name ASC');
        res.json(rows);
    } catch (error) {
        console.error('Error fetching inventory items:', error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Crear un nuevo insumo en el inventario
app.post('/api/inventory', authenticateToken, isAdmin, async (req, res) => {
    const { name, quantity, unit } = req.body;
    if (!name || quantity === undefined || !unit) {
        return res.status(400).json({ message: 'Nombre, cantidad y unidad son requeridos.' });
    }
    try {
        const { rows } = await pool.query(
            'INSERT INTO inventory_items (name, quantity, unit) VALUES ($1, $2, $3) RETURNING *',
            [name, Number(quantity), unit]
        );
        res.status(201).json(rows[0]);
    } catch (error) {
        if (error.code === '23505') { // unique_violation
            return res.status(400).json({ message: "El insumo ya existe." });
        }
        console.error('Error creating inventory item:', error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

// Actualizar la cantidad de un insumo (añadir o restar)
app.patch('/api/inventory/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { change } = req.body;
    const userId = req.user.userId; // Obtenemos el ID del usuario desde el token

    if (change === undefined || isNaN(Number(change))) {
        return res.status(400).json({ message: 'El campo "change" numérico es requerido.' });
    }

    const client = await pool.connect(); // Usar una transacción para seguridad
    try {
        await client.query('BEGIN');

        // 1. Obtener estado actual del ítem
        const currentItemRes = await client.query('SELECT quantity FROM inventory_items WHERE id = $1 FOR UPDATE', [id]);
        if (currentItemRes.rows.length === 0) {
            throw new Error('Insumo no encontrado');
        }
        const quantity_before = currentItemRes.rows[0].quantity;
        const quantity_after = Number(quantity_before) + Number(change);

        // 2. Actualizar el insumo
        const updatedItem = await client.query(
            'UPDATE inventory_items SET quantity = $1 WHERE id = $2 RETURNING *',
            [quantity_after, id]
        );

        // 3. Insertar el registro en el log
        await client.query(
            `INSERT INTO inventory_logs (item_id, user_id, change_amount, quantity_before, quantity_after)
             VALUES ($1, $2, $3, $4, $5)`,
            [id, userId, Number(change), quantity_before, quantity_after]
        );

        await client.query('COMMIT');
        res.json(updatedItem.rows[0]);

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error actualizando inventario con log:', error);
        res.status(500).json({ message: error.message || "Error interno del servidor" });
    } finally {
        client.release();
    }
});

// AÑADIR este nuevo endpoint para obtener los logs
app.get('/api/inventory/:id/logs', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const { rows } = await pool.query(`
            SELECT l.*, u.email as user_email
            FROM inventory_logs l
            JOIN users u ON l.user_id = u.id
            WHERE l.item_id = $1
            ORDER BY l.created_at DESC
            LIMIT 50; -- Limitar para no sobrecargar
        `, [id]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching inventory logs:', error);
        res.status(500).json({ message: "Error al obtener historial de insumo" });
    }
});

// Eliminar un insumo del inventario
app.delete('/api/inventory/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM inventory_items WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Insumo no encontrado.' });
        }
        res.status(204).send(); // 204 No Content
    } catch (error) {
        console.error('Error deleting inventory item:', error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});


// ===================================
//  4.c ENDPOINTS DE EDICIÓN DE LOTES (NUEVO)
// ===================================

// Actualizar la fecha de un lote
app.patch('/api/batches/:batchId/date', authenticateToken, isAdmin, async (req, res) => {
    const { batchId } = req.params;
    const { date } = req.body;
    if (!date) {
        return res.status(400).json({ message: 'La fecha es requerida.' });
    }
    try {
        const { rows } = await pool.query(
            'UPDATE bread_batches SET date = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
            [date, batchId]
        );
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Lote no encontrado.' });
        }
        
        // Emitir un evento para que los clientes actualicen los datos del lote específico
        // Es más eficiente que recargar todo
        io.emit('batch:updated', { 
            batchId: parseInt(batchId),
            updatedData: { date: rows[0].date } 
        });

        res.json(rows[0]);
    } catch (error) {
        console.error('Error updating batch date:', error);
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
//  6. MANEJO DE ERRORES GLOBAL
// ===================================

// Middleware para manejo de errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'production' ? 'Algo salió mal!' : err.message
    });
});

// Manejo de rutas no encontradas
app.use('*', (req, res) => {
    res.status(404).json({ 
        message: 'Ruta no encontrada',
        path: req.originalUrl
    });
});

// ===================================
//  7. INICIO DEL SERVIDOR
// ===================================

server.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Servidor backend corriendo en puerto ${port}`);
    console.log(`📡 Socket.IO escuchando para conexiones en tiempo real`);
    console.log(`🌍 Entorno: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Frontend URL: ${frontendURL}`);
});
