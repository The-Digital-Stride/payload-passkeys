import { buildDevConfig } from '../../dev/buildConfig.js'

/**
 * The single config with a Postgres pool of three connections: the smallest that leaves
 * refuseSignInUnless's re-read a connection while a sign-in's transaction holds another
 * (postgresPoolOfTwo.ts says where the third goes). The option does nothing elsewhere.
 */
export default buildDevConfig({
  db: { postgresPoolMax: 3 },
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'single',
})
