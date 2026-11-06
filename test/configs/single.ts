import { buildDevConfig } from '../../dev/buildConfig.js'

export default buildDevConfig({
  // Task 11 types the plugin options; then: plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'single',
})
