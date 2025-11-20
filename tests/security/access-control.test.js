import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import authRoutes from '../../src/routes/authRoutes.js';
import taskRoutes from '../../src/routes/taskRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

describe('SECURITY TEST - Access Control (REQ-ACCESS-001, REQ-ACCESS-002)', () => {
  let user1Token, user2Token;
  let user1TaskId;

  beforeEach(async () => {
    // Create user 1
    const username1 = 'user1' + Date.now();
    await request(app)
      .post('/api/auth/register')
      .send({ username: username1, password: 'Password123!' });
    
    const login1 = await request(app)
      .post('/api/auth/login')
      .send({ username: username1, password: 'Password123!' });
    user1Token = login1.body.token;

    // Create user 2
    const username2 = 'user2' + Date.now();
    await request(app)
      .post('/api/auth/register')
      .send({ username: username2, password: 'Password123!' });
    
    const login2 = await request(app)
      .post('/api/auth/login')
      .send({ username: username2, password: 'Password123!' });
    user2Token = login2.body.token;

    // Create a task for user 1
    const taskResponse = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({
        title: 'User 1 private task',
        description: 'Private data'
      });
    user1TaskId = taskResponse.body.id;
  });

  it('should prevent user2 from reading user1 tasks', async () => {
    const response = await request(app)
      .get(`/api/tasks/${user1TaskId}`)
      .set('Authorization', `Bearer ${user2Token}`);

    expect(response.status).toBe(404);
  });

  it('should prevent user2 from updating user1 tasks', async () => {
    const response = await request(app)
      .put(`/api/tasks/${user1TaskId}`)
      .set('Authorization', `Bearer ${user2Token}`)
      .send({
        title: 'Attempted change',
        description: 'Unauthorized modification'
      });

    expect(response.status).toBe(404);
  });

  it('should prevent user2 from deleting user1 tasks', async () => {
    const response = await request(app)
      .delete(`/api/tasks/${user1TaskId}`)
      .set('Authorization', `Bearer ${user2Token}`);

    expect(response.status).toBe(404);
  });

  it('should only show own tasks in GET /api/tasks', async () => {
    // Create task for user 2
    await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${user2Token}`)
      .send({
        title: 'User 2 task',
        description: 'Another private task'
      });

    // Fetch user 1's tasks
    const response = await request(app)
      .get('/api/tasks')
      .set('Authorization', `Bearer ${user1Token}`);

    expect(response.status).toBe(200);
    expect(response.body).toBeInstanceOf(Array);
    
    // Should only contain user1's tasks
    const user1Tasks = response.body.filter(task => task.id === user1TaskId);
    expect(user1Tasks.length).toBeGreaterThan(0);
    
    // Should not contain "User 2 task"
    const user2Tasks = response.body.filter(task => task.title === 'User 2 task');
    expect(user2Tasks.length).toBe(0);
  });

  it('should allow user to read their own tasks', async () => {
    const response = await request(app)
      .get(`/api/tasks/${user1TaskId}`)
      .set('Authorization', `Bearer ${user1Token}`);

    expect(response.status).toBe(200);
    expect(response.body.id).toBe(user1TaskId);
    expect(response.body.title).toBe('User 1 private task');
  });
});