const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { connectDB, getConnectionStatus, closeDB } = require('./config/db');
const { csrfProtection, ALLOWED_ORIGINS } = require('./middleware/csrf');

dotenv.config();

const app = express();

// Trust reverse proxy (Render, Cloudflare) for secure cookie handling and HTTPS detection
app.set('trust proxy', 1);

const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://tameererekhta.org',
  'https://www.tameererekhta.org',
  'https://tameer-e-rekhta.vercel.app',
];

if (process.env.FRONTEND_URL) {
  const custom = process.env.FRONTEND_URL.replace(/\/$/, '');
  if (!allowedOrigins.includes(custom)) {
    allowedOrigins.push(custom);
  }
}

if (process.env.ALLOWED_ORIGINS) {
  process.env.ALLOWED_ORIGINS.split(',').forEach((orig) => {
    const trimmed = orig.trim().replace(/\/$/, '');
    if (trimmed && !allowedOrigins.includes(trimmed)) {
      allowedOrigins.push(trimmed);
    }
  });
}

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin) || (origin.endsWith('.vercel.app') && origin.includes('tameer'))) {
        callback(null, true);
      } else if (process.env.NODE_ENV !== 'production') {
        callback(null, true); // Dev fallback
      } else {
        callback(new Error(`CORS rejected: Origin '${origin}' is not authorized.`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Department'],
  })
);

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));

// Lightweight zero-dependency cookie parser
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach((cookie) => {
      const parts = cookie.split('=');
      const name = parts[0].trim();
      const value = parts.slice(1).join('=').trim();
      if (name) {
        try {
          req.cookies[name] = decodeURIComponent(value);
        } catch {
          req.cookies[name] = value;
        }
      }
    });
  }
  next();
});

// CSRF Defense on state-changing requests
app.use(csrfProtection);

// Health Check
app.get('/api/health', (req, res) => {
  const dbStatus = getConnectionStatus();
  res.json({
    status: 'online',
    service: "Ta'meer-e-Rekhta Backend API",
    database: {
      status: dbStatus.isConnected ? 'connected' : 'offline_controlled_mode',
      mode: dbStatus.mode,
      readyState: dbStatus.readyState,
      state: dbStatus.state,
      host: dbStatus.host,
      database: dbStatus.dbName,
    },
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Production Database Fallback Guard: Prevent silent fallback to in-memory storage in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.path !== '/api/health') {
    const dbStatus = getConnectionStatus();
    if (!dbStatus.isConnected) {
      return res.status(503).json({
        success: false,
        error: 'Database service is unavailable. In-memory operations are disabled in production.',
      });
    }
  }
  next();
});

// Mount Routes
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/assessments', require('./routes/assessment.routes'));
app.use('/api/volunteer', require('./routes/volunteer.routes'));
app.use('/api/donate', require('./routes/donate.routes'));
app.use('/api/contact', require('./routes/contact.routes'));
app.use('/api/events', require('./routes/events.routes'));
app.use('/api/media', require('./routes/media.routes'));
app.use('/api/gallery', require('./routes/gallery.routes'));
app.use('/api/hr', require('./routes/hr.routes').router);
app.use('/api', require('./routes/hr.routes').router);
app.use('/api/finance', require('./routes/finance.routes').router);
app.use('/api', require('./routes/finance.routes').router);
app.use('/api', require('./routes/portal.routes'));

const PORT = process.env.PORT || 5000;
let serverInstance = null;
let isShuttingDown = false;

const gracefulShutdown = async (signal = 'SIGTERM', exitCode = 0) => {
  if (isShuttingDown) {
    console.log(`[Backend Shutdown] Shutdown already in progress. Ignoring repeated signal: ${signal}`);
    return;
  }
  isShuttingDown = true;
  console.log(`[Backend Shutdown] Received ${signal}. Initiating graceful shutdown sequence...`);

  // 1. Stop accepting new HTTP requests
  if (serverInstance && serverInstance.listening) {
    let shutdownTimer = null;
    await new Promise((resolve) => {
      shutdownTimer = setTimeout(() => {
        console.error('[Backend Shutdown] Forcing shutdown after timeout (10s).');
        if (process.env.NODE_ENV !== 'test') {
          process.exit(1);
        }
        resolve();
      }, 10000);
      shutdownTimer.unref();

      serverInstance.close((err) => {
        if (shutdownTimer) clearTimeout(shutdownTimer);
        if (err) console.error('[Backend Shutdown] Error closing HTTP listener:', err.message);
        else console.log('[Backend Shutdown] HTTP server stopped accepting connections.');
        resolve();
      });

      if (typeof serverInstance.closeIdleConnections === 'function') {
        serverInstance.closeIdleConnections();
      }
    });
  }

  // 2. Close Mongoose database connection pool
  try {
    await closeDB(false);
    console.log('[Backend Shutdown] Mongoose database connection closed cleanly.');
  } catch (err) {
    console.error('[Backend Shutdown] Error closing Mongoose connection:', err.message);
  }

  console.log(`[Backend Shutdown] Graceful shutdown completed cleanly. Exit code: ${exitCode}.`);
  if (process.env.NODE_ENV !== 'test') {
    process.exit(exitCode);
  }
};

const setupGracefulShutdown = (httpServer) => {
  serverInstance = httpServer;
  process.once('SIGTERM', () => gracefulShutdown('SIGTERM', 0));
  process.once('SIGINT', () => gracefulShutdown('SIGINT', 0));
};

const startServer = async () => {
  // In test mode, block live database connection unless TEST_USE_LIVE_DB is explicitly 'true'
  if (process.env.NODE_ENV === 'test' && process.env.TEST_USE_LIVE_DB !== 'true') {
    console.log('[Backend Server] Test mode: Skipping live connectDB (test isolation enforced).');
  } else {
    try {
      await connectDB();
    } catch (err) {
      console.error(`[Backend Startup Error] ${err.message}`);
      if (process.env.NODE_ENV === 'production') {
        process.exit(1);
      }
      return null;
    }
  }

  if (process.env.NODE_ENV !== 'test') {
    const httpServer = app.listen(PORT, () => {
      console.log(`[Ta'meer-e-Rekhta Backend] Service online at port ${PORT}`);
    });
    setupGracefulShutdown(httpServer);
    return httpServer;
  }
  return null;
};

// Start server when executed directly as main process in non-test environments
if (require.main === module && process.env.NODE_ENV !== 'test') {
  startServer();
} else if (process.env.NODE_ENV === 'test') {
  // In test mode, block live DB connection by default; permit ONLY when TEST_USE_LIVE_DB === 'true'
  if (process.env.TEST_USE_LIVE_DB === 'true') {
    connectDB().catch(() => null);
  } else {
    console.log('[Backend Server] Test mode: Live database connection blocked by default (TEST_USE_LIVE_DB!=true).');
  }
}

// Attach lifecycle controls to app
app.startServer = startServer;
app.gracefulShutdown = gracefulShutdown;
app.isShuttingDown = () => isShuttingDown;
app.setServerInstance = (inst) => { serverInstance = inst; };

module.exports = app;
