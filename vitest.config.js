import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      reportsDirectory: './coverage',
      thresholds: {
        lines: 80,       // minimum line coverage
        functions: 80,   // minimum function coverage
        branches: 75,    // minimum branch coverage
        statements: 80,  // minimum statement coverage
      },
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.test.js',
        '**/*.spec.js',
      ],
      all: true,
    },
  },
});

