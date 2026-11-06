import type { SanitizedConfig } from 'payload'

import { getPayload } from 'payload'
import { parseArgs } from 'util'

import { resetPasskeys } from '../server/reset.js'

const USAGE = 'Usage: payload passkeys:reset --collection <slug> (--email <email> | --id <id>)'

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

const readArgs = () => {
  try {
    // payload/bin.js leaves argv as [node, bin.js, 'passkeys:reset', ...flags] (Payload 3.90.2).
    const { values } = parseArgs({
      allowPositionals: true,
      args: process.argv.slice(2),
      options: {
        collection: { type: 'string' },
        email: { type: 'string' },
        id: { type: 'string' },
      },
    })
    return values
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    return null
  }
}

/**
 * Run by Payload's CLI as `payload passkeys:reset`. Payload logs a failed script but still exits 0
 * (payload/dist/bin/index.js), so this sets the exit code itself.
 */
export const script = async (config: SanitizedConfig): Promise<void> => {
  const values = readArgs()
  if (!values?.collection || (!values.email && !values.id)) {
    console.error(USAGE)
    process.exit(2)
  }
  try {
    const payload = await getPayload({ config })
    const result = await resetPasskeys({
      collection: values.collection,
      email: values.email,
      id: values.id,
      payload,
    })
    console.log(
      `Removed ${plural(result.removedPasskeys, 'passkey', 'passkeys')} and signed out ${plural(result.removedSessions, 'session', 'sessions')} for ${values.collection} ${String(result.userId)}. Their password still works.`,
    )
    process.exit(0)
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  }
}
