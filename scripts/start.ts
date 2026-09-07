import * as fs from 'fs'
import { Daemon, isLegacyConfigFile } from '../dist/daemon/index.js'

// Inject serialization prefix from environment (FATAL if missing)
if (!process.env.VERITY_SERIALIZATION_PREFIX) {
  console.error('[FATAL] VERITY_SERIALIZATION_PREFIX not set')
  process.exit(1)
}
;(globalThis as any).VERITY_SERIALIZATION_PREFIX = Number(process.env.VERITY_SERIALIZATION_PREFIX)

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

let configFile = '/app/config/nsecbunker.json'
const configFlagIndex = process.argv.indexOf('--config')
if (configFlagIndex > -1 && process.argv.length > configFlagIndex + 1) {
    configFile = process.argv[configFlagIndex + 1]
}

if (fs.existsSync(configFile)) {
  try {
    const fileConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'))
    if (isLegacyConfigFile(fileConfig)) {
      console.error(
        '[FATAL] nsecbunker.json contains legacy key material (admin.key / keys.admin / npubs).\n' +
        'Remove key material from nsecbunker.json. Daemon identity is now configured via:\n' +
        '  SIGNER_DAEMON_KEY (ML-DSA-44 hex), SIGNER_DAEMON_ECDH_KEY (secp256k1 hex),\n' +
        '  and SIGNER_UID (identity guard). Admin allow-list uses uid-based env vars.'
      )
      process.exit(1)
    }
  } catch (err: any) {
    console.warn(`WARNING: Failed to parse config file ${configFile}`)
  }
}

const adminUids = (process.env.ADMIN_UIDS || '')
  .split(',')
  .map((r) => r.trim())
  .filter(Boolean)

const relays = (process.env.RELAYS || '').split(',').map((r) => r.trim()).filter(Boolean)
if (relays.length === 0) {
    console.warn("WARNING: RELAYS env var is empty or missing")
}

const config = {
  nostr: {
    relays
  },
  admin: {
    adminRelays: relays,
    allowedUids: adminUids
  },
  database: process.env.DATABASE_URL || `file:/app/config/nsecbunker.db`,
  logs: process.env.AUDIT_LOG_PATH || '/app/logs/audit',
  verbose: true,
  authPort: parseInt(process.env.PORT || '3000', 10),
  authHost: '0.0.0.0'
}

try {
  const daemon = new Daemon(config as any)
  await daemon.start()
} catch (error: any) {
  console.error(`Fatal error starting Daemon:`, error)
  process.exit(1)
}
