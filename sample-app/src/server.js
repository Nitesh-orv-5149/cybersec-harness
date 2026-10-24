import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ordersRouter from './routes/orders.js';
import usersRouter from './routes/users.js';
import toolsRouter from './routes/tools.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));

app.use('/api', ordersRouter);
app.use('/api', usersRouter);
app.use('/api/tools', toolsRouter);

// Built frontend (see build.mjs). Falls back to source if not built.
app.use(express.static(path.join(here, '..', 'dist', 'public')));

const port = Number(process.env.PORT || 3000);
app.listen(port, '127.0.0.1', () => {
  console.log(`sample app listening on http://127.0.0.1:${port}`);
});
