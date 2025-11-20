import { describe, it, expect } from 'vitest';
import request from 'supertest';
import express from 'express';
import authRoutes from '../../src/routes/authRoutes.js';
import taskRoutes from '../../src/routes/taskRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  const message = process.env.NODE_ENV === 'production' 
    ? 'An error occurred' 
    : err.message;
  res.status(err.status || 500).json({ error: message });
});

describe('SECURITY TEST - Error Handling (REQ-DATA-001)', () => {
  
  it('should not expose database details in error messages', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'does_not_exist',
        password: 'WrongPassword123!'
      });

    expect(response.status).toBe(401);
    expect(response.body.error.toLowerCase()).not.toContain('database');
    expect(response.body.error.toLowerCase()).not.toContain('sql');
    expect(response.body.error.toLowerCase()).not.toContain('table');
  });

  it('should give generic error message on failed login', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'test',
        password: 'wrong'
      });

    expect(response.status).toBe(401);
    expect(response.body.error).toMatch(/invalid credentials/i);
  });

  it('should not reveal if username exists', async () => {
    const username1 = 'exists' + Date.now();
    
    // Try with non-existent user
    const response1 = await request(app)
      .post('/api/auth/login')
      .send({ username: 'does_not_exist_' + Date.now(), password: 'Test123!' });

    // Register user
    await request(app)
      .post('/api/auth/register')
      .send({ username: username1, password: 'Test123!' });

    // Try with existing user but wrong password
    const response2 = await request(app)
      .post('/api/auth/login')
      .send({ username: username1, password: 'WrongPassword123!' });

    // Both should give same error
    expect(response1.body.error).toBe(response2.body.error);
  });

  it('should not expose stack traces in responses', async () => {
    const response = await request(app)
      .get('/api/tasks/invalid-id')
      .set('Authorization', 'Bearer invalid-token');

    expect(response.body.stack).toBeUndefined();
    expect(JSON.stringify(response.body)).not.toContain('at ');
  });
});
