import { beforeEach } from 'vitest';

// Global test setup
beforeEach(() => {
  // Reset any global state if needed
});


// ============================================
// FILE: tests/security/input-validation.test.js
// ============================================
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import taskRoutes from '../../routes/taskRoutes.js';
import authRoutes from '../../routes/authRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

describe('SECURITY TEST - Input Validation (REQ-INJ-001)', () => {
  let authToken;
  
  beforeEach(async () => {
    // Register and login test user
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'testuser' + Date.now(), password: 'Test123!' });
    
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'testuser' + Date.now(), password: 'Test123!' });
    
    authToken = loginRes.body.token;
  });

  it('should reject XSS attempt in title', async () => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: '<script>alert("xss")</script>',
        description: 'Normal description'
      });

    expect(response.status).toBe(201);
    expect(response.body.title).not.toContain('<script>');
    expect(response.body.title).not.toContain('alert');
  });

  it('should reject SQL injection attempt in description', async () => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: 'Normal title',
        description: "'; DROP TABLE tasks--"
      });

    expect(response.status).toBe(201);
    expect(response.body.description).not.toContain('DROP TABLE');
  });

  it('should reject prototype pollution attempt', async () => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: '__proto__',
        description: 'Prototype pollution attempt'
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('Invalid input');
  });

  it('should validate title length maximum', async () => {
    const longTitle = 'A'.repeat(101);
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: longTitle,
        description: 'Test'
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('100 characters');
  });

  it('should reject empty title', async () => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: '',
        description: 'Test'
      });

    expect(response.status).toBe(400);
  });

  it('should reject whitespace-only title', async () => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: '   ',
        description: 'Test'
      });

    expect(response.status).toBe(400);
  });

  it('should trim whitespace from inputs', async () => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        title: '  My Task  ',
        description: '  My Description  '
      });

    expect(response.status).toBe(201);
    expect(response.body.title).toBe('My Task');
    expect(response.body.description).toBe('My Description');
  });
});