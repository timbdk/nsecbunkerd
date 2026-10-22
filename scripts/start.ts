import * as fs from 'fs'
import { Daemon } from '../dist/daemon/index.js'

// Inject serialization prefix from environment (FATAL if missing)
if (!process.env.VERITY_SERIALIZATION_PREFIX) {
  console.error('[FATAL] VERITY_SERIALIZATION_PREFIX not set')
  process.exit(1)
}
;(globalThis as any).VERITY_SERIALIZATION_PREFIX = Number(process.env.VERITY_SERIALIZATION_PREFIX)

// Gracefully exit on SIGTERM from Docker restart/stop.
// In container environments where Bun runs as PID 1, the kernel does not supply
// default signal handlers; an explicit SIGTERM listener prevents Docker from
// hanging for the full 10-second stop timeout before issuing SIGKILL.
process.on('SIGTERM', () => {
  process.exit(0)
})

try {
  // Ensure config folder exists at the absolute path used by DATABASE_URL
  const configPath = '/app/config'
  if (!fs.existsSync(configPath)) {
    fs.mkdirSync(configPath, { recursive: true })
  }

  // Database paths
  const dbPath = `${configPath}/nsecbunker.db`
  const templatePath = '/app/prisma/template.db'

  // Check if we should use pre-baked template or run migrations
  if (!fs.existsSync(dbPath) && fs.existsSync(templatePath)) {
    // Fast path: Use pre-baked template (testing with tmpfs)
    fs.copyFileSync(templatePath, dbPath)
  }
} catch (error: any) {
  console.error(`[MIGRATION] Error: ${error.message || error}`)
  process.exit(1)
}

if (!process.env.ADMIN_UIDS) {
  console.error('[FATAL] ADMIN_UIDS not set')
  process.exit(1)
}
const adminUids = process.env.ADMIN_UIDS
  .split(',')
  .map((r) => r.trim())
  .filter(Boolean)

if (!process.env.RELAYS) {
  console.error('[FATAL] RELAYS not set')
  process.exit(1)
}
const relays = process.env.RELAYS.split(',').map((r) => r.trim()).filter(Boolean)
if (relays.length === 0) {
  console.error('[FATAL] RELAYS env var is empty')
  process.exit(1)
}

if (!process.env.DATABASE_URL) {
  console.error('[FATAL] DATABASE_URL not set')
  process.exit(1)
}

const config = {
  nostr: {
    relays
  },
  admin: {
    adminRelays: relays,
    allowedUids: adminUids
  },
  database: process.env.DATABASE_URL,
  logs: '/app/logs/audit',
  verbose: true,
  authPort: 3000,
  authHost: '0.0.0.0'
}

try {
  const daemon = new Daemon(config as any)
  await daemon.start()
} catch (error: any) {
  console.error(`Fatal error starting Daemon:`, error)
  process.exit(1)
}
