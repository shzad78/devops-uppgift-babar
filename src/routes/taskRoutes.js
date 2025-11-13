const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { validateTask } = require('../middleware/validation');
const taskService = require('../services/taskService');

// All task routes require authentication
router.use(authenticateToken);

// CREATE - POST /api/tasks
router.post('/', validateTask, (req, res) => {
  const { title, description } = req.body;
  const task = taskService.createTask(title, description, req.user);
  res.status(201).json(task);
});

// READ - GET /api/tasks (all tasks)
router.get('/', (req, res) => {
  const tasks = taskService.getAllTasks(req.user);
  res.json(tasks);
});

// READ - GET /api/tasks/:id (single task)
router.get('/:id', (req, res) => {
  const task = taskService.getTaskById(req.params.id, req.user);
  if (!task) {
    return res.status(404).json({ error: 'Task not found' });
  }
  res.json(task);
});

// UPDATE - PUT /api/tasks/:id
router.put('/:id', validateTask, (req, res) => {
  const { title, description, completed } = req.body;
  const task = taskService.updateTask(
    req.params.id,
    { title, description, completed },
    req.user
  );
  
  if (!task) {
    return res.status(404).json({ error: 'Task not found' });
  }
  res.json(task);
});

// DELETE - DELETE /api/tasks/:id
router.delete('/:id', (req, res) => {
  const deleted = taskService.deleteTask(req.params.id, req.user);
  if (!deleted) {
    return res.status(404).json({ error: 'Task not found' });
  }
  res.status(204).send();
});

module.exports = router;