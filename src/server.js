const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./config/db');

dotenv.config();

// Connect MongoDB Atlas
connectDB();

const app = express();

const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://tameererekhta.org',
  'https://www.tameererekhta.org',
  'https://tameer-e-rekhta.vercel.app',
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.vercel.app')) {
        callback(null, true);
      } else {
        callback(null, true); // Dev fallback
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    service: "Ta'meer-e-Rekhta Backend API",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Mount Routes
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/volunteer', require('./routes/volunteer.routes'));
app.use('/api/donate', require('./routes/donate.routes'));
app.use('/api/contact', require('./routes/contact.routes'));
app.use('/api/events', require('./routes/events.routes'));
app.use('/api/media', require('./routes/media.routes'));
app.use('/api/gallery', require('./routes/gallery.routes'));
app.use('/api', require('./routes/portal.routes'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`[Ta'meer-e-Rekhta Backend] Service online at port ${PORT}`);
});

module.exports = app;
