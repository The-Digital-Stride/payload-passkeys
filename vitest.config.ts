import path from 'path'
import { loadEnv } from 'payload/node'
import { fileURLToPath } from 'url'
import tsconfigPaths from 'vite-tsconfig-paths'
import { defineConfig } from 'vitest/config'

const dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig(() => {
  loadEnv(path.resolve(dirname, './dev'))

  return {
    plugins: [tsconfigPaths({ ignoreConfigErrors: true, projects: ['./dev/tsconfig.json'] })],
    test: {
      projects: [
        {
          extends: true,
          test: { environment: 'node', include: ['test/unit/**/*.spec.ts'], name: 'unit' },
        },
        {
          extends: true,
          test: {
            env: {
              NODE_ENV: 'test',
              PAYLOAD_DROP_DATABASE: 'true',
              PAYLOAD_SECRET: 'integration-test-secret-not-for-production',
            },
            environment: 'node',
            fileParallelism: false,
            globalSetup: ['test/globalSetup.ts'],
            hookTimeout: 120_000,
            include: ['test/int/**/*.int.spec.ts'],
            name: 'int',
            pool: 'forks',
            testTimeout: 60_000,
          },
        },
      ],
    },
  }
})
