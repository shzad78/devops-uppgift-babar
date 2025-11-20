# Task Management API

A RESTful API for managing tasks with user authentication built using Node.js and Express.

## Description

This is a task management API that allows users to create, read, update, and delete tasks. The API includes user authentication using JWT (JSON Web Tokens) and bcrypt for password hashing. Each user can only access and manage their own tasks.

### Features

- User registration and login
- JWT-based authentication
- CRUD operations for tasks
- User-specific task management
- Input validation middleware
- Error handling

## Prerequisites

- Node.js (v14 or higher recommended)
- npm (Node Package Manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd task-management-api
```

2. Install dependencies:
```bash
npm install
```

## Running Locally

Start the server:
```bash
npm start
```

The server will start on `http://localhost:3000`

You should see the message:
```
Server running on http://localhost:3000
```

### API Endpoints

#### Authentication
- `POST /api/auth/register` - Register a new user
  - Body: `{ "username": "string", "password": "string" }`
- `POST /api/auth/login` - Login and receive JWT token
  - Body: `{ "username": "string", "password": "string" }`

#### Tasks (Requires Authentication)
All task endpoints require a valid JWT token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

- `POST /api/tasks` - Create a new task
  - Body: `{ "title": "string", "description": "string" }`
- `GET /api/tasks` - Get all tasks for the authenticated user
- `GET /api/tasks/:id` - Get a specific task by ID
- `PUT /api/tasks/:id` - Update a task
  - Body: `{ "title": "string", "description": "string", "completed": boolean }`
- `DELETE /api/tasks/:id` - Delete a task

## Running Tests

The project uses Vitest as the testing framework.

### Run all tests:
```bash
npm test
```

### Run tests in watch mode:
```bash
npm run test:watch
```

### Run tests with coverage:
```bash
npm run test:coverage
```

### Run tests with UI:
```bash
npm run test:ui
```

## Project Structure

```
task-management-api/
├── src/
│   ├── middleware/
│   │   ├── auth.js          # JWT authentication middleware
│   │   └── validation.js    # Input validation middleware
│   ├── routes/
│   │   ├── authRoutes.js    # Authentication routes
│   │   └── taskRoutes.js    # Task CRUD routes
│   ├── services/
│   │   ├── authService.js   # Authentication business logic
│   │   └── taskService.js   # Task management business logic
│   └── server.js            # Express app setup
├── tests/                   # Test files
├── package.json
└── README.md
```

## Dependencies

- **express** - Web framework
- **bcrypt** - Password hashing
- **jsonwebtoken** - JWT token generation and verification

## Dev Dependencies

- **vitest** - Testing framework
- **supertest** - HTTP assertions for testing
- **@vitest/coverage-v8** - Code coverage
- **@vitest/ui** - Test UI

## License

ISC
