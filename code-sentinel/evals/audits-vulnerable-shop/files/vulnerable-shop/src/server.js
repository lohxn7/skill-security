// FIXTURE: falhas intencionais para validar o CODE SENTINEL. Nao copie este codigo.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken'); // dependencia NAO declarada no package.json
const db = require('./db');
const { calculateAverageRating } = require('./pricing');

const app = express();
app.use(express.json());

const JWT_SECRET = 'super-secret-jwt-key-123';
const AWS_ACCESS_KEY_ID = 'AKIAZ7XQ3MPL2KDN8RTW';
const sessionCache = {};

app.get('/users', (req, res) => {
  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => {
    if (err) return res.status(500).json({ error: err.stack });
    res.json(rows);
  });
});

app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));
});

app.delete('/admin/users/:id', (req, res) => {
  db.remove(req.params.id);
  res.sendStatus(204);
});

app.get('/files', (req, res) => {
  fs.readFile(path.join(__dirname, 'uploads', req.query.name), (err, data) => res.send(data));
});

app.post('/login', (req, res) => {
  const user = db.findUser(req.body.username);
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  console.log('login attempt', req.body.username, req.body.password);
  if (!user || user.passwordHash !== hash) return res.sendStatus(401);
  const token = Math.random().toString(36).slice(2);
  sessionCache[token] = user;
  res.json({ token, jwt: jwt.sign({ id: user.id }, JWT_SECRET) });
});

app.post('/calc', (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

app.get('/profile', (req, res) => {
  const prefs = JSON.parse(req.headers['x-profile']);
  res.json(prefs);
});

app.get('/products/:id/rating', (req, res) => {
  const ratings = db.ratingsFor(req.params.id);
  res.json({ average: calculateAverageRating(ratings) });
});

app.post('/notify', async (req, res) => {
  const recipients = req.body.recipients;
  recipients.forEach(async (r) => {
    await db.sendMail(r, 'Promo');
  });
  res.json({ queued: recipients.length });
});

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync('config.json', 'utf8'));
  } catch (e) {}
}

setInterval(() => db.cleanup(), 60000);

app.listen(3000, () => console.log('listening', AWS_ACCESS_KEY_ID.length, loadConfig()));
