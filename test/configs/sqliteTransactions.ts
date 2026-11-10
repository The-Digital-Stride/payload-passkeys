import { buildDevConfig } from '../../dev/buildConfig.js'

/**
 * The single config on SQLite with transactions on (`transactionOptions: {}`), which
 * @payloadcms/db-sqlite leaves off by default. The option does nothing on MongoDB or Postgres.
 */
export default buildDevConfig({
  db: { sqliteTransactions: true },
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'single',
})
