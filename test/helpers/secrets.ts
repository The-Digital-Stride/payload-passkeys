export const SECRET_KEYS = [
  'hash',
  'salt',
  'sessions',
  'apiKey',
  'apiKeyIndex',
  'resetPasswordToken',
  'resetPasswordExpiration',
  '_verificationToken',
  'passkeyUserHandle',
  'publicKey',
  'counter',
] as const

/** Every secret key found anywhere in a JSON value, with its path. */
export const findSecretKeys = (value: unknown, path = '$'): string[] => {
  if (Array.isArray(value)) return value.flatMap((item, i) => findSecretKeys(item, `${path}[${i}]`))
  if (!value || typeof value !== 'object') return []
  return Object.entries(value).flatMap(([key, child]) => [
    ...((SECRET_KEYS as readonly string[]).includes(key) ? [`${path}.${key}`] : []),
    ...findSecretKeys(child, `${path}.${key}`),
  ])
}
