const users = new Map();
const sessions = new Map();

function register(username, password) {
  if (users.has(username)) {
    throw new Error('User already exists');
  }
  users.set(username, { username, password });
  return { username };
}

function login(username, password) {
  const user = users.get(username);
  if (!user || user.password !== password) {
    throw new Error('Invalid credentials');
  }
  
  const token = generateToken();
  sessions.set(token, username);
  return token;
}

function generateToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const username = sessions.get(token);
  if (!username) {
    return res.status(403).json({ error: 'Invalid token' });
  }
  
  req.user = username;
  next();
}

module.exports = { register, login, authenticateToken };

