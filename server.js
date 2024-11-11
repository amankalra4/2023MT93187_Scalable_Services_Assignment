const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db/index');
const { REGISTER, SELECT_QUERY, LOGIN, USER_ID_URI, PORT, USERNAME_URI } = require('./constants');
const { authenticateToken } = require('./utils');
require('dotenv').config();

const app = express();
app.use(express.json());

app.post(REGISTER, async (req, res) => {
    try {
      const { username, password, role } = req.body;
      const [existingUser] = await db.query(`${SELECT_QUERY} WHERE username = ?`, [username]);

      if (existingUser.length > 0) {
        return res.status(400).json({ error: 'User already exists' });
      }

      const result = await db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, password, role]);

      res.status(201).json({ message: 'User created successfully', userId: result.insertId });
    } catch (error) {
      res.status(500).json({ error: 'Error creating user' });
    }
});

app.post(LOGIN, async (req, res) => {
    try {
      const { username, password } = req.body;
      const [user] = await db.query(`${SELECT_QUERY} WHERE username = ?`, [username]);
      
      if (user.length === 0) {
        return res.status(400).json({ error: 'User not found' });
      }

      if (user[0].password !== password) {
        return res.status(400).json({ error: 'Incorrect password' });
      }
  
      const token = jwt.sign({ id: user[0].id, role: user[0].role }, process.env.JWT_SECRET, { expiresIn: '1h' });
      
      res.json({ token });
    } catch (error) {
      res.status(500).json({ error: 'Error logging in' });
    }
});

app.put(USER_ID_URI, authenticateToken, async (req, res) => {
    try {
        const userId = req.params.id;
        const { username } = req.body;
    
        if (!username) {
            return res.status(400).send('Please provide at least one field to update');
        }
    
        const updates = [];
        if (username) updates.push(`username = '${username}'`);
    
        const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ${userId}`;
    
        const result = await db.query(sql, [userId]);

        if (result.affectedRows === 0) {
            return res.status(404).send('User not found');
        }

        res.status(200).send('User details updated successfully');
    } catch (error) {
        res.status(500).json({ error: error.sqlMessage });
    }
});

app.get(USERNAME_URI, authenticateToken, async (req, res) => {
  try {
    const { username } = req.params;

    const [user] = await db.query('SELECT id, username, role FROM users WHERE username = ?', [username]);

    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user[0]);
  } catch (error) {
    console.error('Error retrieving user data:', error);
    res.status(500).json({ error: 'Error retrieving user data' });
  }
});

app.delete(USERNAME_URI, authenticateToken, async (req, res) => {
  try {
    const { username } = req.params;

    const [result] = await db.query('DELETE FROM users WHERE username = ?', [username]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User account deleted successfully' });
  } catch (error) {
    console.error('Error deleting user account:', error);
    res.status(500).json({ error: 'Error deleting user account' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
