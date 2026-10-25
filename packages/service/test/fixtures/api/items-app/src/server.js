import express from 'express';
import itemsRouter from './routes/items.js';

const app = express();
app.get('/health', (req, res) => res.json({ ok: true }));
app.use('/api', itemsRouter);
app.listen(Number(process.env.PORT || 3000), '127.0.0.1');
