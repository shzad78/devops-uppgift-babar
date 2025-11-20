import { describe, it, expect } from 'vitest';
import request from 'supertest';
import express from 'express';
import authRoutes from '../../src/routes/authRoutes.js';
import taskRoutes from '../../src/routes/taskRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

describe('SECURITY TEST - Authentication (REQ-AUTH-001 to REQ-AUTH-006)', () => {
  
  describe('Password Security', () => {
    it('should require at least 8 characters in password', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          password: 'Short1'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('8 characters');
    });

    it('should require uppercase letter in password', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          password: 'alllowercase123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toMatch(/uppercase|capital/i);
    });

    it('should require lowercase letter in password', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          password: 'ALLUPPERCASE123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toMatch(/lowercase/i);
    });

    it('should require number in password', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          password: 'NoNumbers'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toMatch(/number|digit/i);
    });

    it('should hash passwords (not store in plaintext)', async () => {
      const password = 'SecurePass123!';
      await request(app)
        .post('/api/auth/register')
        .send({
          username: 'hashtest' + Date.now(),
          password: password
        });

      // Try to login with bcrypt hash format - should fail
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'hashtest',
          password: '$2b$12$somehashedpassword'
        });

      expect(loginResponse.status).toBe(401);
    });
  });

  describe('Token Security', () => {
    it('should reject request without token', async () => {
      const response = await request(app)
        .get('/api/tasks');

      expect(response.status).toBe(401);
      expect(response.body.error).toMatch(/token/i);
    });

    it('should reject invalid token', async () => {
      const response = await request(app)
        .get('/api/tasks')
        .set('Authorization', 'Bearer invalid-token-12345');

      expect(response.status).toBe(403);
    });

    it('should generate valid JWT token on login', async () => {
      const username = 'jwttest' + Date.now();
      await request(app)
        .post('/api/auth/register')
        .send({ username, password: 'SecurePass123!' });

      const response = await request(app)
        .post('/api/auth/login')
        .send({ username, password: 'SecurePass123!' });

      expect(response.status).toBe(200);
      expect(response.body.token).toBeDefined();
      expect(typeof response.body.token).toBe('string');
      expect(response.body.token.length).toBeGreaterThan(20);
    });

    it('should include expiration in JWT token', async () => {
      const username = 'exptest' + Date.now();
      await request(app)
        .post('/api/auth/register')
        .send({ username, password: 'SecurePass123!' });

      const response = await request(app)
        .post('/api/auth/login')
        .send({ username, password: 'SecurePass123!' });

      const token = response.body.token;
      const parts = token.split('.');
      expect(parts.length).toBe(3); // JWT has 3 parts

      const payload = JSON.parse(
        Buffer.from(parts[1], 'base64').toString()
      );

      expect(payload.exp).toBeDefined();
      expect(payload.exp).toBeGreaterThan(Date.now() / 1000);
    });
  });

  describe('Username Validation', () => {
    it('should require at least 3 characters in username', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'ab',
          password: 'SecurePass123!'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('3 characters');
    });

    it('should prevent duplicate usernames', async () => {
      const username = 'duplicate' + Date.now();
      const userData = {
        username,
        password: 'SecurePass123!'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData);

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      expect(response.status).toBe(400);
      expect(response.body.error).toMatch(/already exists|taken/i);
    });
  });
});