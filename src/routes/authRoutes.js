const express = require('express');
const router = express.Router();
const { register, login } = require('../middleware/auth');
const { validateAuth } = require('../middleware/validation');

router.post('/register', validateAuth, (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = register(username, password);
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error) {
    next({ status: 400, message: error.message });
  }
});

router.post('/login', validateAuth, (req, res, next) => {
  try {
    const { username, password } = req.body;
    const token = login(username, password);
    res.json({ message: 'Login successful', token });
  } catch (error) {
    next({ status: 401, message: error.message });
  }
});

module.exports = router;