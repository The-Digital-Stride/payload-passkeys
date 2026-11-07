import { buildDevConfig } from '../../dev/buildConfig.js'

export default buildDevConfig({
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'multi',
})
