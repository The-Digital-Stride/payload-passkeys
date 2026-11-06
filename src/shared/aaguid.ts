const NAMES: Record<string, string> = {
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
}

export const providerName = (aaguid: null | string | undefined): null | string =>
  (aaguid && NAMES[aaguid.toLowerCase()]) || null
