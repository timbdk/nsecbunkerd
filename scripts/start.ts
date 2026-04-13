import * as fs from 'fs'
import { Daemon } from '../dist/daemon/index.js'
import { NDKPrivateKeySigner } from '@nostr-dev-kit/ndk'

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

let adminKey = process.env.ADMIN_KEY
let adminNpubs = process.env.ADMIN_NPUBS ? process.env.ADMIN_NPUBS.split(',').map(r => r.trim()).filter(Boolean) : []

if (fs.existsSync(configFile)) {
    try {
        const fileConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'))
        if (fileConfig?.admin?.key && !adminKey) adminKey = fileConfig.admin.key
        if (fileConfig?.admin?.npubs && adminNpubs.length === 0) adminNpubs = fileConfig.admin.npubs
    } catch (err) {
        console.warn(`WARNING: Failed to parse config file ${configFile}`)
    }
}

if (!adminKey) {
    console.log("Generating new ephemeral admin key for session...")
    adminKey = NDKPrivateKeySigner.generate().privateKey
}

if (adminKey && adminKey.length !== 64 && !adminKey.startsWith('nsec')) {
    adminKey = adminKey.trim()
}

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
    npubs: adminNpubs,
    key: adminKey
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
