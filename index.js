// File: index.js

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// ------------------------------------------------------------
// 1. Hardcoded Secret (Vulnerability #1)
// ------------------------------------------------------------
const SECRET_API_KEY = "MY_SUPER_SECRET_KEY_12345"; // Hardcoded secret

// ------------------------------------------------------------
// 2. Initialize SQLite DB
// ------------------------------------------------------------
const db = new sqlite3.Database(':memory:'); // in-memory DB
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
  );`);
  // Insert a test user
  db.run(`INSERT INTO users (username, password) VALUES ('alice', 'password123')`);
});

// ------------------------------------------------------------
// 3. SQL Injection Endpoint (Vulnerability #2)
// ------------------------------------------------------------
// Accepts GET /user?id=<value>
app.get('/user', (req, res) => {
  const userId = req.query.id; 
  // **VULNERABLE:** Directly concatenating user input into SQL string
  const query = `SELECT * FROM users WHERE id = ${userId};`;
  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).send("SQL error: " + err.message);
    }
    res.json(rows);
  });
});

// ------------------------------------------------------------
// 4. Command Injection Endpoint (Vulnerability #3)
// ------------------------------------------------------------
// Accepts GET /run-cmd?cmd=<value>
app.get('/run-cmd', (req, res) => {
  const userCmd = req.query.cmd; 
  console.log(userCmd);
  // **VULNERABLE:** Directly inserting user input into a shell command
  exec(`ls ${userCmd}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(`Error: ${stderr}`);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// ------------------------------------------------------------
// 5. Path Traversal Endpoint (Vulnerability #4)
// ------------------------------------------------------------
// Accepts GET /read-file?file=<filename>
app.get('/read-file', (req, res) => {
  const userFile = req.query.file; 
  // **VULNERABLE:** Not sanitizing user input, allowing “../” sequences
  const filePath = path.join(__dirname, userFile);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send(`Cannot read file: ${err.message}`);
    }
    res.send(`<pre>${data}</pre>`);
  });
});

// ------------------------------------------------------------
// 6. Reflected XSS Endpoint (Vulnerability #5)
// ------------------------------------------------------------
// Accepts GET /greet?name=<value>
app.get('/greet', (req, res) => {
  const userName = req.query.name || 'Guest';
  // **VULNERABLE:** Embedding unsanitized user input into HTML
  res.send(`
    <html>
      <body>
        <h1>Hello, ${userName}!</h1>
        <p>Welcome to our site.</p>
      </body>
    </html>
  `);
});

// ------------------------------------------------------------
// 7. Insecure Eval (Bonus Vulnerability #6)
// ------------------------------------------------------------
// Accepts POST /calculate with JSON body: { "expr": "<expression>" }
app.post('/calculate', (req, res) => {
    console.log(req.body);
  const expression = req.body.expr;
  // **VULNERABLE:** Using eval on user-supplied expression
  try {
    const result = eval(expression);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: "Invalid expression" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable app listening on port ${PORT}`);
  console.log(`Hardcoded secret is: ${SECRET_API_KEY}`);
});
