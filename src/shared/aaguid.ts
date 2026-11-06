import { AAGUID_NAMES } from './aaguids.generated.js'

/** A display name for the passkey's provider, or null. Display only: never a security decision. */
export const providerName = (aaguid: null | string | undefined): null | string =>
  (aaguid && AAGUID_NAMES[aaguid.toLowerCase()]) || null
