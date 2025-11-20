const express = require('express');
const router = express.Router();
const { register, login } = require('../middleware/auth');
const { validateAuth } = require('../middleware/validation');

router.post('/register', validateAuth, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await register(username, password);
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Basic validation without complexity requirements
    if (!username || !password) {
      const err = new Error('Username and password are required');
      err.status = 400;
      return next(err);
    }

    const token = await login(username, password);
    res.json({ message: 'Login successful', token });
  } catch (error) {
    const err = new Error(error.message);
    err.status = 401;
    next(err);
  }
});

module.exports = router;