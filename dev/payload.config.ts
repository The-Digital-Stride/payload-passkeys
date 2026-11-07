import path from 'path'
import { fileURLToPath } from 'url'

import { buildDevConfig } from './buildConfig.js'

// As in Payload's plugin template: generate:importmap looks for app/(payload) under ROOT_DIR.
if (!process.env.ROOT_DIR) {
  process.env.ROOT_DIR = path.dirname(fileURLToPath(import.meta.url))
}

export default buildDevConfig({ variant: 'single' })
