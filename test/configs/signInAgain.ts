import { buildDevConfig } from '../../dev/buildConfig.js'

/** The single config for sites whose admins sign in with SSO: no password re-entry (1.1.0). */
export default buildDevConfig({
  plugin: {
    limits: { anonymousChallenges: 50, passkeysPerUser: 3 },
    reauthentication: 'sign-in-again',
  },
  variant: 'single',
})
