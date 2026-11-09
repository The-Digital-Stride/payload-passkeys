import { defineConfig, devices } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const dirname = path.dirname(fileURLToPath(import.meta.url))
const tmp = path.resolve(dirname, 'test/.tmp')
// libSQL creates the database file but not its folder.
mkdirSync(tmp, { recursive: true })

export default defineConfig({
  forbidOnly: !!process.env.CI,
  fullyParallel: false,
  projects: [
    {
      name: 'chromium',
      testIgnore: '**/signInAgain.e2e.spec.ts',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      // A second dev app with reauthentication: 'sign-in-again' (SSO sites), on its own port.
      name: 'sign-in-again',
      testMatch: '**/signInAgain.e2e.spec.ts',
      use: { ...devices['Desktop Chrome'], baseURL: 'http://localhost:3001' },
    },
  ],
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  retries: process.env.CI ? 1 : 0,
  testDir: 'test/e2e',
  testMatch: '**/*.e2e.spec.ts',
  // The first request to each admin route compiles it, which can take a while in `next dev`.
  timeout: 120_000,
  use: { baseURL: 'http://localhost:3000', trace: 'retain-on-failure' },
  webServer: [
    {
      command: 'pnpm dev',
      // The dev app on SQLite with a throwaway file, so e2e needs no database service. Each start
      // drops it, and the dev config seeds the dev user.
      env: {
        DATABASE_ADAPTER: 'sqlite',
        DATABASE_URL: `file:${path.join(tmp, 'e2e.db')}`,
        PAYLOAD_DROP_DATABASE: 'true',
        // Turns on the dev-only endpoint that ages a session (dev/buildConfig.ts).
        PAYLOAD_E2E: 'true',
        PAYLOAD_SECRET: 'e2e-secret-not-for-production',
      },
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      url: 'http://localhost:3000/admin/login',
    },
    {
      // Own port, build folder and database file; the importmap and types are shared and neither
      // is regenerated here (PAYLOAD_E2E turns type generation off).
      command: 'pnpm dev --port 3001',
      env: {
        DATABASE_ADAPTER: 'sqlite',
        DATABASE_URL: `file:${path.join(tmp, 'e2e-sign-in-again.db')}`,
        NEXT_DIST_DIR: '.next-sign-in-again',
        PASSKEYS_REAUTHENTICATION: 'sign-in-again',
        PAYLOAD_DROP_DATABASE: 'true',
        PAYLOAD_E2E: 'true',
        PAYLOAD_PUBLIC_SERVER_URL: 'http://localhost:3001',
        PAYLOAD_SECRET: 'e2e-secret-not-for-production',
      },
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      url: 'http://localhost:3001/admin/login',
    },
  ],
  // One worker: the specs share the dev app's database and one virtual authenticator.
  workers: 1,
})
