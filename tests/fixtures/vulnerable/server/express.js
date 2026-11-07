const express = require('express');
const { exec } = require('child_process');

const app = express();

app.post('/api/charge', async (req, res) => {
  await db.charges.create({ data: req.body });
  res.json({ ok: true });
});

app.get('/api/convert', (req, res) => {
  exec(`convert ${req.query.file} -resize 200x200 out.png`, (error) => {
    res.json({ ok: !error });
  });
});

module.exports = app;
