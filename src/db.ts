import type { PrismaClient } from '@prisma/client'

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

  // Dynamically load Prisma dependencies so importing modules that reference
  // db (e.g. in unit tests) does not fail if Prisma client is not pre-generated.
  const { PrismaClient } = require('@prisma/client')
  const { PrismaLibSql } = require('@prisma/adapter-libsql')

  const url = process.env.DATABASE_URL ?? 'file:/app/config/nsecbunker.db'

  // Pass the config object directly — PrismaLibSql calls createClient itself
  const adapter = new PrismaLibSql({ url })

  _prisma = new PrismaClient({ adapter, log: [...logLevel] })
  return _prisma
}

export function setPrismaClient(client: PrismaClient | null): void {
  _prisma = client
}

// Proxy keeps every call-site's existing `prisma.xxx` syntax intact.
const prisma = new Proxy({} as PrismaClient, {
  get(_target, prop) {
    if (_prisma && prop in _prisma) {
      return (_prisma as any)[prop]
    }
    return (getPrisma() as any)[prop]
  },
  set(_target, prop, value) {
    if (!_prisma) {
      _prisma = {} as any
    }
    ;(_prisma as any)[prop] = value
    return true
  }
})

export default prisma
