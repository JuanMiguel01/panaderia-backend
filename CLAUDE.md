# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev    # Development with auto-reload (nodemon)
npm start      # Production start
```

No test runner is configured (`npm test` exits with an error). No linter is configured.

## Architecture

The entire backend lives in a single file: `server.js`. There are no separate route, controller, or service layers — all Express route handlers are defined inline alongside middlewares and utilities.

`config/database.js` exists but is **not used** by `server.js`; the server creates its own `pg.Pool` directly from `DATABASE_URL`.

### Database schema

There are no migration files. `initDB()` runs at startup and issues `CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements to evolve the schema in place. Tables expected to already exist (created externally before first deploy): `users`, `bread_batches`, `sales`, `inventory_items`, `inventory_logs`. Tables created automatically: `bread_presets`, `cuadre_gastos`, `partner_funds`, `partner_fund_movements`, `debts`.

### Auth & authorization

JWT is verified in `authenticateToken` middleware (Bearer token in `Authorization` header). Three roles: `admin`, `manager`, `employee`. A granular `permissions` JSON object (stored in the `users` row) is embedded in the JWT payload and controls per-user capabilities (e.g. `canViewStockCard`, `canDeleteSales`). Most financial/admin routes are protected by `isAdmin`.

### Real-time layer

Every mutating operation emits a Socket.IO event so the frontend can update without polling. Events: `user:registered`, `user:approved`, `batch:created`, `batch:deleted`, `batch:updated`, `sale:created`, `sale:updated`, `sale:deleted`. The server never processes incoming Socket.IO messages from clients — it only emits.

### Key business logic

- **Inventory `PATCH /api/inventory/:id`**: Uses a transaction + `FOR UPDATE` lock. Applies a **weighted-average cost** formula when adding stock with an explicit `unit_cost`.
- **`POST /api/fondos/cierre/:date`**: Daily closing inside a transaction. Computes `utilidadNeta = ventas - costoInsumos - gastosGenerales`, then splits it equally among the three fixed partners (`jm`, `michel`, `nadiel`), subtracting each partner's individual expenses. Also updates the `general` (cash) fund by `totalVentas - gastosFondo`.
- **Route ordering**: `/api/inventory/daily/:date` must be declared before `/api/inventory/:id` to prevent `"daily"` being parsed as a numeric ID — this is already the case in `server.js`.

### Environment variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Full Postgres connection string (production: Neon) |
| `JWT_SECRET` | HS256 signing key |
| `PORT` | Server port (default `3001`) |
| `NODE_ENV` | `production` enables SSL, disables request logging, and strips error details from responses |
| `FRONTEND_URL` | Allowed CORS origin for both Express and Socket.IO (dev default: `http://localhost:5173`) |

Development uses individual `DB_*` variables (`DB_USER`, `DB_HOST`, `DB_DATABASE`, `DB_PASSWORD`, `DB_PORT`) only when `DATABASE_URL` is absent.

### Deployment

Deployed to **Render** (free tier) with **Neon** as the serverless PostgreSQL host. `render.yaml` defines the service. The frontend is expected at `FRONTEND_URL` (e.g. a Vercel deployment).
