const express = require('express'), http = require('http'), fs = require('fs'), { Server } = require('socket.io');
const Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const db = new Database('meet.db');
db.exec('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)');
const app = express();
// Optional HTTPS (needed for camera access on any host other than localhost): set SSL_KEY and SSL_CERT paths.
const server = process.env.SSL_KEY ? require('https').createServer({ key: fs.readFileSync(process.env.SSL_KEY), cert: fs.readFileSync(process.env.SSL_CERT) }, app) : http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e6 });
app.use(express.json()); app.use(express.static('public'));
const tok = (id, u) => ({ token: jwt.sign({ id, username: u }, SECRET, { expiresIn: '7d' }), username: u });
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!/^\w{3,20}$/.test(username || '') || !password || password.length < 6) return res.status(400).json({ error: 'Username (3-20 letters/numbers/_) and 6+ char password required' });
  try { const r = db.prepare('INSERT INTO users(username,password) VALUES(?,?)').run(username, bcrypt.hashSync(password, 10)); res.json(tok(r.lastInsertRowid, username)); }
  catch { res.status(400).json({ error: 'Username already taken' }); }
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(req.body.username || '');
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password)) return res.status(400).json({ error: 'Invalid credentials' });
  res.json(tok(u.id, u.username));
});
// Authenticated real-time signalling
io.use((s, next) => { try { s.user = jwt.verify(s.handshake.auth.token, SECRET); next(); } catch { next(new Error('auth')); } });
io.on('connection', s => {
  s.on('join', async room => {
    room = String(room).slice(0, 40); s.room = room;
    const others = [...(await io.in(room).fetchSockets())].map(x => ({ id: x.id, name: x.user.username }));
    s.join(room); s.emit('peers', others);
  });
  s.on('signal', ({ to, data }) => io.to(to).emit('signal', { from: s.id, name: s.user.username, data }));
  s.on('draw', d => s.room && s.to(s.room).emit('draw', d));
  s.on('clear', () => s.room && s.to(s.room).emit('clear'));
  s.on('disconnect', () => s.room && s.to(s.room).emit('left', s.id));
});
server.listen(process.env.PORT || 3003, () => console.log('Meet running on port ' + (process.env.PORT || 3003)));
