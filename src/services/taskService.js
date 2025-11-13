const tasks = new Map();
let taskIdCounter = 1;

function createTask(title, description, owner) {
  const task = {
    id: taskIdCounter++,
    title: title.trim(),
    description: description?.trim() || '',
    completed: false,
    owner,
    createdAt: new Date().toISOString()
  };
  
  tasks.set(task.id, task);
  return task;
}

function getAllTasks(owner) {
  return Array.from(tasks.values()).filter(task => task.owner === owner);
}

function getTaskById(id, owner) {
  const task = tasks.get(parseInt(id));
  if (!task || task.owner !== owner) {
    return null;
  }
  return task;
}

function updateTask(id, updates, owner) {
  const task = getTaskById(id, owner);
  if (!task) {
    return null;
  }
  
  if (updates.title !== undefined) {
    task.title = updates.title.trim();
  }
  if (updates.description !== undefined) {
    task.description = updates.description.trim();
  }
  if (updates.completed !== undefined) {
    task.completed = Boolean(updates.completed);
  }
  
  task.updatedAt = new Date().toISOString();
  return task;
}

function deleteTask(id, owner) {
  const task = getTaskById(id, owner);
  if (!task) {
    return false;
  }
  
  return tasks.delete(parseInt(id));
}

module.exports = {
  createTask,
  getAllTasks,
  getTaskById,
  updateTask,
  deleteTask
};