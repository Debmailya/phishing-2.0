import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeUrl } from './analyzer.js';

const app = express();
const port = Number(process.env.PORT || 3000);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"]
      }
    }
  })
);

app.use(
  '/api/',
  rateLimit({
    windowMs: 60 * 1000,
    limit: 45,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Rate limit exceeded. Please wait a moment and try again.'
    }
  })
);

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

app.post('/api/scan', (req, res) => {
  try {
    const { url } = req.body ?? {};
    if (typeof url !== 'string') {
      return res.status(400).json({ error: 'Request body must include a URL string.' });
    }

    const report = analyzeUrl(url);
    return res.status(200).json(report);
  } catch (error) {
    return res.status(400).json({
      error: error instanceof Error ? error.message : 'Unable to scan URL.'
    });
  }
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`PhishGuard AI running on http://localhost:${port}`);
});
