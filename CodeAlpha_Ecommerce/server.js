const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const db = new Database('shop.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, description TEXT, price INTEGER, image TEXT, stock INTEGER);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, total INTEGER, address TEXT, status TEXT DEFAULT 'Processing', created DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(order_id INTEGER, product_id INTEGER, qty INTEGER, price INTEGER);`);
if (!db.prepare('SELECT COUNT(*) c FROM products').get().c) {
  const ins = db.prepare('INSERT INTO products(name,description,price,image,stock) VALUES(?,?,?,?,?)');
  [['Wireless Mouse','Ergonomic 2.4GHz wireless mouse.',1200,'🖱️',50],['Mechanical Keyboard','Blue-switch keyboard, full size.',4500,'⌨️',30],
   ['USB-C Hub','7-in-1 hub with HDMI and card reader.',3200,'🔌',40],['Laptop Stand','Adjustable aluminium stand.',2800,'💻',25],
   ['Headphones','Over-ear headphones with mic.',3900,'🎧',35],['Webcam HD','1080p webcam for calls.',3500,'📷',20],
   ['Flash Drive 64GB','USB 3.0 flash drive.',900,'💾',100],['Power Bank 10000mAh','Fast-charging power bank.',2500,'🔋',45]].forEach(p => ins.run(...p));
}
const app = express(); app.use(express.json()); app.use(express.static('public'));
const tok = (id, u) => ({ token: jwt.sign({ id, username: u }, SECRET, { expiresIn: '7d' }), username: u });
const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').slice(7), SECRET); next(); } catch { res.status(401).json({ error: 'Please log in' }); } };

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) return res.status(400).json({ error: 'Username and a 6+ character password are required' });
  try { const r = db.prepare('INSERT INTO users(username,password) VALUES(?,?)').run(username.trim(), bcrypt.hashSync(password, 10)); res.json(tok(r.lastInsertRowid, username.trim())); }
  catch { res.status(400).json({ error: 'Username already taken' }); }
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(req.body.username || '');
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password)) return res.status(400).json({ error: 'Invalid credentials' });
  res.json(tok(u.id, u.username));
});
app.get('/api/products', (req, res) => res.json(db.prepare('SELECT * FROM products').all()));
app.get('/api/products/:id', (req, res) => { const p = db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id); p ? res.json(p) : res.status(404).json({ error: 'Not found' }); });
app.post('/api/orders', auth, (req, res) => {
  const { items, address } = req.body;
  if (!Array.isArray(items) || !items.length || !address) return res.status(400).json({ error: 'Cart and address are required' });
  try {
    const id = db.transaction(() => {
      let total = 0; const lines = [];
      for (const it of items) {
        const p = db.prepare('SELECT * FROM products WHERE id=?').get(it.id), q = parseInt(it.qty);
        if (!p || !(q > 0) || p.stock < q) throw new Error(`"${p ? p.name : 'Item'}" is unavailable in that quantity`);
        total += p.price * q; lines.push([p, q]);
      }
      const o = db.prepare('INSERT INTO orders(user_id,total,address) VALUES(?,?,?)').run(req.user.id, total, address);
      for (const [p, q] of lines) {
        db.prepare('INSERT INTO order_items VALUES(?,?,?,?)').run(o.lastInsertRowid, p.id, q, p.price);
        db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(q, p.id);
      }
      return o.lastInsertRowid;
    })();
    res.json({ orderId: id });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/orders', auth, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id);
  orders.forEach(o => o.items = db.prepare('SELECT p.name,i.qty,i.price FROM order_items i JOIN products p ON p.id=i.product_id WHERE order_id=?').all(o.id));
  res.json(orders);
});
app.listen(process.env.PORT || 3000, () => console.log('Shop running on http://localhost:' + (process.env.PORT || 3000)));
