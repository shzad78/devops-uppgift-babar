function validateTask(req, res, next) {
  const { title, description } = req.body;
  
  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    return res.status(400).json({ error: 'Title is required and must be a non-empty string' });
  }
  
  if (title.length > 100) {
    return res.status(400).json({ error: 'Title must be less than 100 characters' });
  }
  
  if (description && typeof description !== 'string') {
    return res.status(400).json({ error: 'Description must be a string' });
  }
  
  if (description && description.length > 500) {
    return res.status(400).json({ error: 'Description must be less than 500 characters' });
  }
  
  next();
}

function validateAuth(req, res, next) {
  const { username, password } = req.body;
  
  if (!username || typeof username !== 'string' || username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  }
  
  if (!password || typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  next();
}

module.exports = { validateTask, validateAuth };
