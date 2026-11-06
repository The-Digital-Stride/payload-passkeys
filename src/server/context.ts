import type { Payload, SanitizedConfig } from 'payload'

import type { ResolvedOptions } from './options.js'

import { PACKAGE_NAME } from '../shared/constants.js'

export const OPTIONS_KEY = PACKAGE_NAME

export const getPasskeysOptions = (payloadOrConfig: Payload | SanitizedConfig): ResolvedOptions => {
  const config = 'config' in payloadOrConfig ? payloadOrConfig.config : payloadOrConfig
  const options = (config.custom as Record<string, unknown> | undefined)?.[OPTIONS_KEY]
  if (!options) throw new Error(`[payload-passkeys] The plugin is not in this Payload config.`)
  return options as ResolvedOptions
}
