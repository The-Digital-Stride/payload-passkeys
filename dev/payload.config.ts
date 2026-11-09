import path from 'path'
import { fileURLToPath } from 'url'

import { buildDevConfig } from './buildConfig.js'

// As in Payload's plugin template: generate:importmap looks for app/(payload) under ROOT_DIR.
if (!process.env.ROOT_DIR) {
  process.env.ROOT_DIR = path.dirname(fileURLToPath(import.meta.url))
}

// The e2e suite starts a second dev app for SSO sites (playwright.config.ts). Unset, nothing changes.
export default buildDevConfig({
  plugin:
    process.env.PASSKEYS_REAUTHENTICATION === 'sign-in-again'
      ? { reauthentication: 'sign-in-again' }
      : {},
  variant: 'single',
})
