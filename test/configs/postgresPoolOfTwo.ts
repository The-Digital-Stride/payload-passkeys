import { buildDevConfig } from '../../dev/buildConfig.js'

/**
 * The single config with a Postgres pool of two connections. @payloadcms/db-postgres 3.90.2 holds
 * one for good from boot (dist/connect.js: connectWithReconnect calls pool.connect() and never
 * releases it; a pool of one can't even boot), so a sign-in's transaction takes the only other one
 * and anything that reads outside the transaction waits for it. The option does nothing elsewhere.
 */
export default buildDevConfig({
  db: { postgresPoolMax: 2 },
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'single',
})
