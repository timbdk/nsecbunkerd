import NDK, { NDKEvent, NDKPrivateKeySigner, NDKRelayAuthPolicies, Nip46PermitCallback, Nip46PermitCallbackParams } from '@nostr-dev-kit/ndk'
import { log, auditSigningRequest, logStartup, logError } from '../lib/logger.js'
import { nip19, utils } from 'nostr-tools'
const { bytesToHex } = utils
import { Backend } from './backend/index.js'
import { IMethod, checkIfPubkeyAllowed } from './lib/acl/index.js'
import AdminInterface from './admin/index.js'
import { IConfig } from '../config/index.js'
import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import prisma from '../db.js'
// Force rebuild for logging
import { DaemonConfig } from './index.js'
import { checkpointService } from '../services/CheckpointService.js'
import { startHttpServer } from './http/server.js'

// Inject serialization prefix from environment (FATAL if missing)
if (!process.env.VERITY_SERIALIZATION_PREFIX) {
  logError('daemon', '[FATAL] VERITY_SERIALIZATION_PREFIX not set')
  process.exit(1)
}
(globalThis as any).VERITY_SERIALIZATION_PREFIX = Number(process.env.VERITY_SERIALIZATION_PREFIX)

export type Key = {
  name: string
  npub?: string
}

export type Session = {
  name: string
  clientPubkey: string
  description?: string
  createdAt: Date
  lastUsedAt?: Date
}



/**
 * Called by the NDKNip46Backend when an action requires authorization
 * @param keyName -- Key attempting to be used
 * @param adminInterface
 * @returns
 */
function signingAuthorizationCallback(keyName: string, adminInterface: AdminInterface): Nip46PermitCallback {
  return async (p: Nip46PermitCallbackParams): Promise<boolean> => {
    const { id, method, pubkey: remotePubkey, params: payload } = p
    const msg = `Request ${id}: ${method} by ${remotePubkey.slice(0, 16)}... for ${keyName}`
    log.signing(msg)

    try {
      const keyAllowed = await checkIfPubkeyAllowed(keyName, remotePubkey, method as IMethod, payload)

      if (keyAllowed === true || keyAllowed === false) {
        // Audit log for signing decisions
        auditSigningRequest({
          timestamp: new Date().toISOString(),
          keyName,
          clientPubkey: remotePubkey,
          method,
          allowed: keyAllowed
        })
        return keyAllowed
      }

      // If undefined (no policy matched), deny by default in Verity
      return false
    } catch (e: any) {
      logError('signing', `Authorization callback error for ${keyName}`, e)
    }

    return false
  }
}

export default async function run(config: DaemonConfig) {
  const daemon = new Daemon(config)
  await daemon.start()
}

export class Daemon {
  public config: DaemonConfig
  private adminInterface: AdminInterface
  public ndk: NDK
  public httpServer: any
  public isReady: boolean = false

  constructor(config: DaemonConfig) {
    this.config = config
    const registrarNpub = process.env.REGISTRAR_NPUB
    this.adminInterface = new AdminInterface(
      {
        ...config.admin,
        registrarNpub
      },
      config
    )

    this.adminInterface.loadNsec = this.loadNsec.bind(this)

    this.ndk = new NDK({
      explicitRelayUrls: config.nostr.relays,
      enableOutboxModel: false,
      autoDeviceDiscovery: false,
      autoFetchUserMutelist: false,
      cacheAdapter: undefined
    })

    // Assign a signer to the NDK instance so it can handle NIP-42 AUTH challenges
    // Using the master key for the daemon's own connection authentication
    log.daemon(`SIGNER_MASTER_KEY: ${process.env.SIGNER_MASTER_KEY ? 'present' : 'missing'}`)
    if (process.env.SIGNER_MASTER_KEY) {
      log.daemon('Daemon NDK Signer configured with Master Key')
      this.ndk.signer = new NDKPrivateKeySigner(process.env.SIGNER_MASTER_KEY)
      // Enable NIP-42 auto-auth so the relay accepts writes from this connection
      this.ndk.relayAuthDefaultPolicy = NDKRelayAuthPolicies.signIn({ ndk: this.ndk })
    }
    this.ndk.pool.on('relay:connect', (r) => {
      log.daemon(`✅ Connected to ${r.url}`)
    })
    this.ndk.pool.on('relay:notice', (n, r) => log.daemon(`Notice from ${r.url}: ${n}`))

    this.ndk.pool.on('relay:disconnect', (r) => {
      log.daemon(`❌ Disconnected from ${r.url}`)
    })
  }



  async startKeys() {
    // Load all encrypted keys from SQLite database
    const { retrieveKey } = await import('../services/KeyService.js')

    const keys = await prisma.key.findMany({
      where: {
        status: 'ACTIVE'
      },
      select: { keyName: true }
    })

    log.keys(`Starting ${keys.length} keys from database`)

    for (const key of keys) {
      try {
        const privateKeyHex = await retrieveKey(key.keyName)
        if (privateKeyHex) {
          log.keys(`Starting key: ${key.keyName}`)
          await this.startKey(key.keyName, privateKeyHex)
        } else {
          logError('keys', `Could not decrypt key: ${key.keyName}`)
        }
      } catch (e: any) {
        logError('keys', `Failed to start key ${key.keyName}`, e)
      }
    }
  }

  async start() {
    // Validate SIGNER_MASTER_KEY is set
    const masterKey = process.env.SIGNER_MASTER_KEY
    if (!masterKey) {
      logError('daemon', 'CRITICAL: SIGNER_MASTER_KEY environment variable not set')
      logError('daemon', 'This key must be provided and should never touch disk.')
      process.exit(1)
    }
    if (masterKey.length !== 64) {
      logError('daemon', 'CRITICAL: SIGNER_MASTER_KEY must be a 64-character hex string (256 bits)')
      process.exit(1)
    }
    logStartup('SIGNER_MASTER_KEY validated')

    // Validate stored encrypted keys (if any)
    try {
      const { validateAllKeys } = await import('../services/KeyService.js')
      const result = await validateAllKeys()

      if (result.failed.length > 0) {
        if (result.failed.length > 5) {
          logError('keys', `Structural key corruption detected (${result.failed.length} failures)`)
          logError('keys', 'Check application logs and database integrity.')
          logError('keys', 'Or restore keys from backup.')
          process.exit(1)
        } else {
          for (const keyName of result.failed) {
            logError('keys', `Key validation failed: ${keyName}`)
          }
          logError('keys', 'Check application logs for decryption failure details.')
          process.exit(1)
        }
      } else if (result.total > 0) {
        logStartup(`Validated ${result.valid}/${result.total} stored keys`)
      }
    } catch (e: any) {
      // May fail if no keys yet, that's OK
      log.keys(`Key validation skipped: ${e.message}`)
    }

    checkpointService.start()
    
    // Retry initial connection to relay indefinitely (fault tolerance for orchestration)
    let connected = false
    let attempts = 0
    const RETRY_DELAY_MS = 2000

    while (!connected) {
      try {
        attempts++
        log.daemon(`Connection attempt ${attempts} to relay...`)
        await this.ndk.connect(5000)
        connected = true
        const user = await this.ndk.signer?.user()
        logStartup(`nsecBunker connected and ready: ${user?.npub || 'unknown identity'} after ${attempts} attempts`)
      } catch (e: any) {
        logError('daemon', `Initial connection failed: ${e.message}`)
        log.daemon(`Retrying in ${RETRY_DELAY_MS}ms...`)
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS))
      }
    }

    if (this.config.authPort) {
      this.httpServer = startHttpServer(this, this.config.authPort, this.config.authHost)
    }
    await this.startKeys()

    this.isReady = true
    logStartup('nsecBunker ready to serve requests')

    // Keep process alive in testing (NDK subscriptions keep prod alive)
    if (process.env.NODE_ENV === 'testing') {
      setInterval(
        () => {
          // No-op to keep event loop active
        },
        1000 * 60 * 60
      )
    }

    process.on('uncaughtException', (e) => {
      logError('daemon', 'CRITICAL: Uncaught Exception:', e)
    })

    process.on('unhandledRejection', (e) => {
      logError('daemon', 'CRITICAL: Unhandled Rejection:', e)
    })
  }

  /**
   * Method to start a key's backend
   * @param name Name of the key
   * @param nsec NSec of the key
   */
  async startKey(name: string, nsec: string) {
    const cb = signingAuthorizationCallback(name, this.adminInterface)
    let hexpk: string

    if (nsec.startsWith('nsec1')) {
      try {
        const key = new NDKPrivateKeySigner(nsec)
        hexpk = key.privateKey!
      } catch (e: any) {
        logError('keys', `Error loading key ${name}`, e)
        return
      }
    } else {
      hexpk = nsec
    }

    const backend = new Backend(this.ndk, hexpk, cb, this.config)
    await backend.start()
  }



  loadNsec(keyName: string, nsec: string) {
    this.startKey(keyName, nsec).catch((e) => {
      logError('keys', `ERROR: Failed to start key ${keyName}:`, e)
    })
  }
}
