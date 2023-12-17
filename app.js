
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { connect } = require('./db');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());


const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
  
    try {
      if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
      }
  
      const decoded = jwt.verify(token, process.env.SECRET_KEY);
      req.user = decoded; 
      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ error: 'Access denied. Invalid token.' });
    }
  };
  
  module.exports = authenticateToken;
  

const checkUserRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    next();
  };
};


app.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

   
    const connection = await connect();
    const [result] = await connection.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [
      username,
      hashedPassword,
      role,
    ]);

    const userId = result.insertId;


    const token = jwt.sign({ userId, username, role }, process.env.SECRET_KEY, { expiresIn: '24h' });

    res.status(201).json({ userId, username, role, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;


    const connection = await connect();
    const [rows] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];

   
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role }, process.env.SECRET_KEY, {
      expiresIn: '24h',
    });

    res.json({ userId: user.id, username: user.username, role: user.role, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/tasks', authenticateToken, (req, res) => {
  const { title, description } = req.body;
  const userId = req.user.userId;


  const connection = connect();
  connection
    .execute('INSERT INTO tasks (title, description, userId) VALUES (?, ?, ?)', [title, description, userId])
    .then((result) => {
      const taskId = result.insertId;
      res.status(201).json({ taskId, title, description, userId });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
});

app.get('/tasks', authenticateToken, (req, res) => {
  const userId = req.user.userId;

 
  const connection = connect();
  connection
    .execute('SELECT * FROM tasks WHERE userId = ?', [userId])
    .then(([rows]) => {
      res.json(rows);
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
});

app.get('/tasks/:id', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const taskId = req.params.id;

 
  const connection = connect();
  connection
    .execute('SELECT * FROM tasks WHERE id = ? AND userId = ?', [taskId, userId])
    .then(([rows]) => {
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Task not found' });
      }
      res.json(rows[0]);
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
});

app.put('/tasks/:id', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const taskId = req.params.id;
  const { title, description } = req.body;

  const connection = connect();
  connection
    .execute('UPDATE tasks SET title = ?, description = ? WHERE id = ? AND userId = ?', [title, description, taskId, userId])
    .then(([result]) => {
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Task not found' });
      }
      res.json({ taskId, title, description, userId });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
});

app.delete('/tasks/:id', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const taskId = req.params.id;


  const connection = connect();
  connection
    .execute('DELETE FROM tasks WHERE id = ? AND userId = ?', [taskId, userId])
    .then(([result]) => {
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Task not found' });
      }
      res.json({ message: 'Task deleted successfully' });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
});

app.get('/tasks/all', authenticateToken, checkUserRole('admin'), (req, res) => {

  const connection = connect();
  connection
    .execute('SELECT * FROM tasks')
    .then(([rows]) => {
      res.json(rows);
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
