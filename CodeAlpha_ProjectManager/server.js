const express = require('express'), http = require('http'), { Server } = require('socket.io');
const Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const db = new Database('pm.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, name TEXT, owner_id INTEGER);
CREATE TABLE IF NOT EXISTS members(project_id INTEGER, user_id INTEGER, PRIMARY KEY(project_id,user_id));
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, project_id INTEGER, title TEXT, description TEXT DEFAULT '', status TEXT DEFAULT 'todo', assignee_id INTEGER);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, task_id INTEGER, user_id INTEGER, body TEXT, created DATETIME DEFAULT CURRENT_TIMESTAMP);`);
const app = express(), server = http.createServer(app), io = new Server(server);
app.use(express.json()); app.use(express.static('public'));
const tok = (id, u) => ({ token: jwt.sign({ id, username: u }, SECRET, { expiresIn: '7d' }), username: u });
const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').slice(7), SECRET); next(); } catch { res.status(401).json({ error: 'Please log in' }); } };
const isMember = (pid, uid) => !!db.prepare('SELECT 1 FROM members WHERE project_id=? AND user_id=?').get(pid, uid);
const guard = (req, res, next) => isMember(req.params.id, req.user.id) ? next() : res.status(403).json({ error: 'Not a member of this project' });
const taskGuard = (req, res, next) => {
  const t = db.prepare('SELECT * FROM tasks WHERE id=?').get(req.params.id);
  if (!t || !isMember(t.project_id, req.user.id)) return res.status(403).json({ error: 'No access to this task' });
  req.task = t; next();
};
const notify = (uid, msg) => io.to('user:' + uid).emit('notify', msg);

io.use((s, next) => { try { s.user = jwt.verify(s.handshake.auth.token, SECRET); next(); } catch { next(new Error('auth')); } });
io.on('connection', s => {
  s.join('user:' + s.user.id);
  s.on('watch', pid => { if (isMember(pid, s.user.id)) { s.rooms.forEach(r => r.startsWith('project:') && s.leave(r)); s.join('project:' + pid); } });
});

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
app.get('/api/projects', auth, (req, res) => res.json(db.prepare('SELECT p.* FROM projects p JOIN members m ON m.project_id=p.id WHERE m.user_id=? ORDER BY p.id DESC').all(req.user.id)));
app.post('/api/projects', auth, (req, res) => {
  if (!(req.body.name || '').trim()) return res.status(400).json({ error: 'Project name required' });
  const r = db.prepare('INSERT INTO projects(name,owner_id) VALUES(?,?)').run(req.body.name.trim(), req.user.id);
  db.prepare('INSERT INTO members VALUES(?,?)').run(r.lastInsertRowid, req.user.id); res.json({ id: r.lastInsertRowid });
});
app.post('/api/projects/:id/members', auth, guard, (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username=?').get(req.body.username || '');
  if (!u) return res.status(404).json({ error: 'No such user' });
  db.prepare('INSERT OR IGNORE INTO members VALUES(?,?)').run(req.params.id, u.id);
  const p = db.prepare('SELECT name FROM projects WHERE id=?').get(req.params.id);
  notify(u.id, `You were added to project "${p.name}"`); io.to('project:' + req.params.id).emit('board'); res.json({ ok: true });
});
app.get('/api/projects/:id', auth, guard, (req, res) => res.json({
  project: db.prepare('SELECT * FROM projects WHERE id=?').get(req.params.id),
  members: db.prepare('SELECT u.username FROM users u JOIN members m ON m.user_id=u.id WHERE m.project_id=?').all(req.params.id),
  tasks: db.prepare('SELECT t.*,u.username assignee FROM tasks t LEFT JOIN users u ON u.id=t.assignee_id WHERE project_id=? ORDER BY t.id').all(req.params.id)
}));
function assigneeId(pid, name) {
  if (!name) return null;
  const u = db.prepare('SELECT u.id FROM users u JOIN members m ON m.user_id=u.id WHERE u.username=? AND m.project_id=?').get(name, pid);
  if (!u) throw new Error('Assignee must be a project member'); return u.id;
}
app.post('/api/projects/:id/tasks', auth, guard, (req, res) => {
  try {
    if (!(req.body.title || '').trim()) throw new Error('Title required');
    const a = assigneeId(req.params.id, req.body.assignee);
    db.prepare('INSERT INTO tasks(project_id,title,description,assignee_id) VALUES(?,?,?,?)').run(req.params.id, req.body.title.trim(), req.body.description || '', a);
    if (a && a !== req.user.id) notify(a, `${req.user.username} assigned you "${req.body.title.trim()}"`);
    io.to('project:' + req.params.id).emit('board'); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.patch('/api/tasks/:id', auth, taskGuard, (req, res) => {
  try {
    const t = req.task;
    if (req.body.status && ['todo', 'doing', 'done'].includes(req.body.status)) db.prepare('UPDATE tasks SET status=? WHERE id=?').run(req.body.status, t.id);
    if ('assignee' in req.body) {
      const a = assigneeId(t.project_id, req.body.assignee);
      db.prepare('UPDATE tasks SET assignee_id=? WHERE id=?').run(a, t.id);
      if (a && a !== req.user.id) notify(a, `${req.user.username} assigned you "${t.title}"`);
    }
    io.to('project:' + t.project_id).emit('board'); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/tasks/:id/comments', auth, taskGuard, (req, res) =>
  res.json(db.prepare('SELECT c.body,c.created,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE task_id=? ORDER BY c.id').all(req.params.id)));
app.post('/api/tasks/:id/comments', auth, taskGuard, (req, res) => {
  const body = (req.body.body || '').trim(); if (!body) return res.status(400).json({ error: 'Empty comment' });
  db.prepare('INSERT INTO comments(task_id,user_id,body) VALUES(?,?,?)').run(req.task.id, req.user.id, body);
  io.to('project:' + req.task.project_id).emit('comment', req.task.id);
  if (req.task.assignee_id && req.task.assignee_id !== req.user.id) notify(req.task.assignee_id, `${req.user.username} commented on "${req.task.title}"`);
  res.json({ ok: true });
});
server.listen(process.env.PORT || 3002, () => console.log('PM tool running on http://localhost:' + (process.env.PORT || 3002)));
