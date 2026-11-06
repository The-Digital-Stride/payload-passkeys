import type { Config } from 'payload'

import type { PasskeysPluginOptions } from './types.js'

export type * from './types.js'

export const passkeysPlugin =
  (_options: PasskeysPluginOptions = {}) =>
  (config: Config): Config =>
    config
