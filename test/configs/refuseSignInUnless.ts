import { buildDevConfig } from '../../dev/buildConfig.js'

/**
 * The single config with trash on the users collection, for refuseSignInUnless (1.2.0). Its own
 * file, so its own test fork: getPayload caches one instance per process.
 */
export default buildDevConfig({
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  trash: true,
  variant: 'single',
})
