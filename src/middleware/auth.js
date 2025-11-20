const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = new Map();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SALT_ROUNDS = 12;

async function register(username, password) {
  if (users.has(username)) {
    throw new Error('Username already exists');
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  users.set(username, { username, password: hashedPassword });
  return { username };
}

async function login(username, password) {
  const user = users.get(username);

  // Use generic error message to not reveal if username exists
  if (!user) {
    throw new Error('Invalid credentials');
  }

  // Compare password with hash
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    throw new Error('Invalid credentials');
  }

  const token = generateToken(username);
  return token;
}

function generateToken(username) {
  // Generate JWT with expiration
  return jwt.sign(
    { username },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.username;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

module.exports = { register, login, authenticateToken };

