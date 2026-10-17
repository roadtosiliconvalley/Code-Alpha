const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const db = new Database('social.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, bio TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT, created DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INTEGER, user_id INTEGER, body TEXT, created DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS likes(post_id INTEGER, user_id INTEGER, PRIMARY KEY(post_id,user_id));
CREATE TABLE IF NOT EXISTS follows(follower_id INTEGER, following_id INTEGER, PRIMARY KEY(follower_id,following_id));`);
const app = express(); app.use(express.json()); app.use(express.static('public'));
const tok = (id, u) => ({ token: jwt.sign({ id, username: u }, SECRET, { expiresIn: '7d' }), username: u });
const verify = req => jwt.verify((req.headers.authorization || '').slice(7), SECRET);
const auth = (req, res, next) => { try { req.user = verify(req); next(); } catch { res.status(401).json({ error: 'Please log in' }); } };
const opt = (req, res, next) => { try { req.user = verify(req); } catch { req.user = { id: 0 }; } next(); };

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
const postQuery = where => `SELECT p.id,p.body,p.created,u.username,
 (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes,
 (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id AND l.user_id=@me) liked
 FROM posts p JOIN users u ON u.id=p.user_id ${where} ORDER BY p.id DESC LIMIT 50`;
function withComments(posts) {
  posts.forEach(p => p.comments = db.prepare('SELECT c.body,c.created,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE post_id=? ORDER BY c.id').all(p.id));
  return posts;
}
app.get('/api/feed', opt, (req, res) => {
  const me = req.user.id;
  const sql = req.query.mode === 'following'
    ? postQuery('WHERE u.id=@me OR u.id IN (SELECT following_id FROM follows WHERE follower_id=@me)') : postQuery('');
  res.json(withComments(db.prepare(sql).all({ me })));
});
app.post('/api/posts', auth, (req, res) => {
  const body = (req.body.body || '').trim();
  if (!body || body.length > 280) return res.status(400).json({ error: 'Post must be 1-280 characters' });
  db.prepare('INSERT INTO posts(user_id,body) VALUES(?,?)').run(req.user.id, body); res.json({ ok: true });
});
app.post('/api/posts/:id/like', auth, (req, res) => {
  const r = db.prepare('DELETE FROM likes WHERE post_id=? AND user_id=?').run(req.params.id, req.user.id);
  if (!r.changes) db.prepare('INSERT OR IGNORE INTO likes VALUES(?,?)').run(req.params.id, req.user.id);
  res.json({ ok: true });
});
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const body = (req.body.body || '').trim();
  if (!body || body.length > 280) return res.status(400).json({ error: 'Comment must be 1-280 characters' });
  db.prepare('INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)').run(req.params.id, req.user.id, body); res.json({ ok: true });
});
app.get('/api/users/:name', opt, (req, res) => {
  const u = db.prepare('SELECT id,username,bio FROM users WHERE username=?').get(req.params.name);
  if (!u) return res.status(404).json({ error: 'User not found' });
  u.followers = db.prepare('SELECT COUNT(*) c FROM follows WHERE following_id=?').get(u.id).c;
  u.following = db.prepare('SELECT COUNT(*) c FROM follows WHERE follower_id=?').get(u.id).c;
  u.isFollowing = !!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id, u.id);
  u.posts = withComments(db.prepare(postQuery('WHERE u.id=@uid')).all({ me: req.user.id, uid: u.id }));
  delete u.id; res.json(u);
});
app.post('/api/users/:name/follow', auth, (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username=?').get(req.params.name);
  if (!u || u.id === req.user.id) return res.status(400).json({ error: 'Cannot follow this user' });
  const r = db.prepare('DELETE FROM follows WHERE follower_id=? AND following_id=?').run(req.user.id, u.id);
  if (!r.changes) db.prepare('INSERT INTO follows VALUES(?,?)').run(req.user.id, u.id);
  res.json({ ok: true });
});
app.put('/api/me', auth, (req, res) => { db.prepare('UPDATE users SET bio=? WHERE id=?').run((req.body.bio || '').slice(0, 160), req.user.id); res.json({ ok: true }); });
app.listen(process.env.PORT || 3001, () => console.log('Social running on http://localhost:' + (process.env.PORT || 3001)));
