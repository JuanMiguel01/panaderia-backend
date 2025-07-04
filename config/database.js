const { Pool } = require('pg');

// Configuración para diferentes entornos
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || undefined,
  // Si no hay DATABASE_URL, usar variables individuales (desarrollo)
  user: process.env.DATABASE_URL ? undefined : process.env.DB_USER,
  host: process.env.DATABASE_URL ? undefined : process.env.DB_HOST,
  database: process.env.DATABASE_URL ? undefined : process.env.DB_DATABASE,
  password: process.env.DATABASE_URL ? undefined : process.env.DB_PASSWORD,
  port: process.env.DATABASE_URL ? undefined : process.env.DB_PORT,
  // SSL para producción
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

module.exports = pool;