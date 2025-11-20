import { describe, it, expect } from 'vitest';
import request from 'supertest';
import app from '../../src/server.js';

describe('Functional: Auth Flow', () => {
  it('should register a new user with valid credentials', async () => {
    const username = 'john' + Date.now();
    const response = await request(app)
      .post('/api/auth/register')
      .send({ username, password: 'SecurePass123!' });

    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('message');
    expect(response.body.user).toHaveProperty('username');
    expect(response.body.user.username).toBe(username);
  });

  it('should login with valid credentials and return a token', async () => {
    const username = 'testuser' + Date.now();
    const password = 'SecurePass123!';

    // Register user first
    await request(app)
      .post('/api/auth/register')
      .send({ username, password });

    // Login with the same credentials
    const response = await request(app)
      .post('/api/auth/login')
      .send({ username, password });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('token');
    expect(typeof response.body.token).toBe('string');
    expect(response.body.token.length).toBeGreaterThan(20);
  });
});
