import type { Config } from 'payload'

export type PasskeysPluginOptions = Record<string, never>

export const passkeysPlugin =
  (_options: PasskeysPluginOptions = {}) =>
  (config: Config): Config =>
    config
