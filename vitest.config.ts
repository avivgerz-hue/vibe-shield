import { defineConfig } from 'vitest/config';

/**
 * Tests run against the TypeScript sources directly (no build required) so a
 * failing test always points at the line that is wrong, not at `dist/`.
 */
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/fixtures/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
    reporters: ['default'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts', 'bin/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'tests/**'],
      thresholds: {
        lines: 70,
        functions: 70,
        statements: 70,
        branches: 65,
      },
    },
  },
});
