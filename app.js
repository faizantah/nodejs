require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const saltRounds = 10;
const secretKey = process.env.SECRET_KEY;

const app = express();
app.use(bodyParser.json());

let db = new sqlite3.Database('./db.sqlite', (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Connected to the SQlite database.');
});

db.run(`CREATE TABLE accounts(
    id INTEGER PRIMARY KEY, 
    first_name TEXT NOT NULL CHECK(length(first_name) <= 100), 
    last_name TEXT NOT NULL CHECK(length(last_name) <= 100), 
    email TEXT NOT NULL CHECK(length(email) <= 100), 
    phone TEXT NOT NULL CHECK(length(phone) <= 16), 
    password TEXT NOT NULL, 
    birthday DATE, 
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
    last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.post('/accounts', authenticate, (req, res) => {
    const { first_name, last_name, email, phone, password, birthday } = req.body;
    if (password.length > 50) {
        return res.status(400).json({ error: 'Password too long' });
    }
    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            return res.status(500).json({ error: 'Error hashing password' });
        }
        db.run(`INSERT INTO accounts(first_name, last_name, email, phone, password, birthday) VALUES(?, ?, ?, ?, ?, ?)`,
            [first_name, last_name, email, phone, hash, birthday], function (err) {
                if (err) {
                    return res.status(500).json({ error: 'Error inserting into database' });
                }
                let mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: 'admin@admin.com',
                    subject: 'New account created',
                    text: `A new account has been created for ${first_name} ${last_name} (${email}).`
                };
                transporter.sendMail(mailOptions, function (err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log('Email sent: ' + info.response);
                    }
                });
                res.json({ id: this.lastID });
            });
    });
});

function authenticate(req, res, next) {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        db.get(`SELECT * FROM accounts WHERE id = ?`, [decoded.id], (err, row) => {
            if (err || !row) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            req.userId = decoded.id;
            next();
        });
    });
}


app.get('/accounts', authenticate, (req, res) => {
    const limit = req.query.limit || 10; // Default limit is 10
    db.all('SELECT * FROM accounts LIMIT ?', [limit], (err, rows) => {
        if (err) {
            throw err;
        }
        res.json(rows);
    });
});

app.get('/accounts/:id', authenticate, (req, res) => {
    const id = req.params.id;
    db.get(`SELECT * FROM accounts WHERE id = ?`, [id], (err, row) => {
        if (err) {
            return console.error(err.message);
        }
        res.json(row);
    });
});

app.post('/accounts', authenticate, (req, res) => {
    const { first_name, last_name, email, phone, password, birthday } = req.body;
    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            return console.log(err);
        }
        db.run(`INSERT INTO accounts(first_name, last_name, email, phone, password, birthday) VALUES(?, ?, ?, ?, ?, ?)`,
            [first_name, last_name, email, phone, hash, birthday], function (err) {
                if (err) {
                    return console.log(err.message);
                }
                res.json({ id: this.lastID });
            });
    });
});

app.put('/accounts/:id/password', authenticate, (req, res) => {
    const id = req.params.id;
    const { password } = req.body;
    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            return console.log(err);
        }
        db.run(`UPDATE accounts SET password = ?, last_modified = CURRENT_TIMESTAMP WHERE id = ?`,
            [hash, id], function (err) {
                if (err) {
                    return console.error(err.message);
                }
                res.json({ changes: this.changes });
            });
    });
});

app.delete('/accounts/:id', authenticate, (req, res) => {
    const id = req.params.id;
    db.run(`DELETE FROM accounts WHERE id = ?`, id, (err) => {
        if (err) {
            return console.error(err.message);
        }
        res.json({ deleted: true });
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});