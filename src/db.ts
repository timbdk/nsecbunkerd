import { PrismaClient } from '@prisma/client'
import { PrismaLibSql } from '@prisma/adapter-libsql'

// Only enable verbose query logging in testing/development
const logLevel =
  process.env.NODE_ENV === 'testing' || process.env.NODE_ENV === 'development'
    ? (['query', 'info', 'warn', 'error'] as const)
    : (['warn', 'error'] as const)

let _prisma: PrismaClient | null = null

/**
 * Return (and lazily create) the PrismaClient singleton.
 *
 * Deferred until first DB access so that scripts/start.ts has already:
 *   1. Created /app/config on the tmpfs mount.
 *   2. Copied the pre-baked template.db into place.
 *
 * In @prisma/adapter-libsql v7+, PrismaLibSql receives the raw libsql
 * Config object (the same thing you'd pass to createClient) — not a
 * pre-created Client instance.  The adapter calls createClient internally.
 */
function getPrisma(): PrismaClient {
  if (_prisma) return _prisma

  const url = process.env.DATABASE_URL ?? 'file:/app/config/nsecbunker.db'

  // Pass the config object directly — PrismaLibSql calls createClient itself
  const adapter = new PrismaLibSql({ url })

  _prisma = new PrismaClient({ adapter, log: [...logLevel] })
  return _prisma
}

// Proxy keeps every call-site's existing `prisma.xxx` syntax intact.
const prisma = new Proxy({} as PrismaClient, {
  get(_target, prop) {
    return (getPrisma() as any)[prop]
  }
})

export default prisma
