import path from 'path'
import { fileURLToPath } from 'url'
import { defineConfig } from 'vitest/config'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    pool: 'threads',
    setupFiles: [],
    include: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
    exclude: ['node_modules/**', 'dist/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html', 'json'],
      include: ['src/config/**/*.ts', 'src/extraction/**/*.ts', 'src/utils/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'test/**',
        'dist/**',
        'src/__mocks__/**',
        'src/types.ts',
        'src/extension.ts',
        'src/commands/**',
        'src/ui/**',
        'src/telemetry/**',
        'src/i18n/**',
      ],
    },
  },
  resolve: {
    alias: {
      'vscode': path.resolve(__dirname, 'src/__mocks__/vscode.ts'),
    },
  },
})
