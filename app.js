// Import required modules
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');

// Initialize the app
const app = express();
const PORT = 3000;
const DATA_FILE = "./database.json";

// Parse incoming requests with JSON payloads
app.use(bodyParser.json());

// Parse incoming requests with urlencoded payloads
app.use(bodyParser.urlencoded({ extended: true }));


// Middleware setup
app.use(
  session({
    name: 'cookieBin',
    secret: 'mysecretkey',
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 3 * 60 * 60 * 1000, // The cookie tends to expire in 3 hours.
      httpOnly: true,
      path: '/',
      sameSite: 'strict' // To mitigate CSRF-attacks
    }
  })
);


// Serve static files
app.use('/public', express.static('public')); // Unprotected routes for login and register

app.use('/protected', (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  next();
});
app.use('/protected', express.static('private/protected')); // Protected routes for authenticated users

// Helper function to read and write to the JSON file
const readData = async () => {
  try {
    const data = await fs.promises.readFile(DATA_FILE);
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading data:', err);
    throw err;
  }
};

const writeData = async (data) => {
  try {
    await fs.promises.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error writing data:', err);
    throw err;
  }
};

// Routes

// Home route
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/public/login.html');
  }
  res.redirect('/protected/index.html');
});

// -----------------------------
// |      Public routes        |
// -----------------------------

// --------------------------------
// |      > Register routes       |
// --------------------------------

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const data = await readData();
    const userExists = data.users.find((u) => u.username === username);

    if (userExists) {
      return res.status(400).send('User already exists');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    data.users.push({ username, password: hashedPassword });
    await writeData(data);
    res.status(201).send('User registered successfully');
  }

  catch (err) {
    return res.status(500).send('Server error');
  }
});


// -----------------------------
// |      > Login routes       |
// -----------------------------

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const data = await readData();
    const user = data.users.find(u => u.username === username);

    const checkPassword = await bcrypt.compare(password, user.password)

    if (!user || !(checkPassword)) {
      return res.status(401).send('Invalid credentials');
    }
    req.session.user = { username };
    res.redirect('/protected/index.html');
  } catch (err) {
    res.status(500).send('Server error');
  }
});



// Dashboard route (protected)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  res.redirect('/protected/dashboard.html');
});

// Add task route
app.post('/add', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  try {
    const data = await readData();
    const taskId = Date.now();
    data.tasks.push({ id: taskId, task: req.body.task, user: req.session.user.username });

    await writeData(data);

    res.redirect('/protected/dashboard.html');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Get tasks for the logged-in user
app.get('/tasks', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  try {
    const data = await readData();
    const userTasks = data.tasks.filter(task => task.user === req.session.user.username);
    res.json(userTasks);
  } catch (err) {
    return res.status(500).send('Server error');
  }
});


// Delete task route
app.delete('/tasks/:id', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  try {
    const data = await readData();
    data.tasks = data.tasks.filter(t => t.id !== parseInt(req.params.id, 10));
    await writeData(data);
    res.send('Task deleted');
  } catch (err) {
    res.status(500).send('Server error');
  }
});


// Logout task
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out');
    }
    res.redirect('/public/login.html');
  });
});


// Server launching
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

