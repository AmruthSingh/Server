# Server
const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors=require('cors');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key';
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const pool = mysql.createPool({
  connectionLimit: 1,
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'users'
});

app.post('/loginpage', (req, res) => {
  const { username, password } = req.body;

  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error getting connection from pool:', err);
      res.status(500).json({ error: 'An error occurred' });
      return;
    }

    const query = `SELECT * FROM logins WHERE username = ? AND password = ?`;
    connection.query(query, [username, password], (err, results) => {
      connection.release();

      if (err) {
        console.error('Error executing the query:', err);
        res.status(500).json({ error: 'An error occurred' });
        return;
      }

      if (results.length === 1) {
        const user = results[0];
        const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1m' });

        res.json({ token });
      } else {
        res.status(401).json({ error: 'Invalid username or password' });
      }
    });
  });
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.userId = decoded.id;
    next();
  });
};

app.get('/home', authenticate, (req, res) => {

  const userId = req.userId;

  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error getting connection from pool:', err);
      res.status(500).json({ error: 'An error occurred' });
      return;
    }

    const query = `SELECT * FROM logins WHERE id = ?`;
    connection.query(query, [userId], (err, results) => {
      connection.release();

      if (err) {
        console.error('Error executing the query:', err);
        res.status(500).json({ error: 'An error occurred' });
        return;
      }

      if (results.length === 1) {
        const user = results[0];
        res.json({ user });
      } else {
        res.status(404).json({ error: 'User not found' });
      }
    });
  });
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
  console.log('conneted to database')
});
