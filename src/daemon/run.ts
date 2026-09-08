import NDK, {
  NDKEvent,
  NDKMlDsaSigner,
  NDKPrivateKeySigner,
  NDKRelayAuthPolicies,
  NDKRelaySet,
  NDKTransportCredential,
  Nip46PermitCallback,
  Nip46PermitCallbackParams
} from '@nostr-dev-kit/ndk'
import { log, auditSigningRequest, logStartup, logError } from '../lib/logger.js'
import { Backend } from './backend/index.js'
import { IMethod, checkIfPubkeyAllowed } from './lib/acl/index.js'
import AdminInterface from './admin/index.js'
import { IConfig, validateDaemonEnvironment, isLegacyConfigFile } from '../config/index.js'
import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import prisma from '../db.js'
// Force rebuild for logging
import { DaemonConfig } from './index.js'
import { checkpointService } from '../services/CheckpointService.js'
import { startHttpServer } from './http/server.js'
import { verifyPlatformChain, findServiceEntry, publicKeyFromSecret } from 'verity-event-data-module'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'
import { KeyFamily, resolveKeyFamily } from '../services/KeyService.js'

// Inject serialization prefix from environment (FATAL if missing)
if (!process.env.VERITY_SERIALIZATION_PREFIX) {
  logError('daemon', '[FATAL] VERITY_SERIALIZATION_PREFIX not set')
  process.exit(1)
}
(globalThis as any).VERITY_SERIALIZATION_PREFIX = Number(process.env.VERITY_SERIALIZATION_PREFIX)

export type Key = {
  name: string
}

export type Session = {
  name: string
  clientPubkey: string
  description?: string
  createdAt: Date
  lastUsedAt?: Date
}

function extractEventKind(method: string, payload?: any): number | undefined {
  if (method !== 'sign_event' || !payload) return undefined
  try {
    if (Array.isArray(payload) && typeof payload[0] === 'string') {
      const event = JSON.parse(payload[0])
      return typeof event.kind === 'number' ? event.kind : undefined
    } else if (typeof payload === 'object' && typeof payload.kind === 'number') {
      return payload.kind
    }
  } catch {}
  return undefined
}

/**
 * Called by the NDKNip46Backend when an action requires authorization.
 * @param keyName -- Key attempting to be used
 */
function signingAuthorizationCallback(keyName: string): Nip46PermitCallback {
  return async (params: Nip46PermitCallbackParams) => {
    log.signing(`🔑 Authorization requested for ${keyName}: ${params.method}`)
    const eventKind = extractEventKind(params.method, params.params)

    try {
      // Fast path: ACL allows without prompt
      const isAllowed = (await checkIfPubkeyAllowed(keyName, params.pubkey, params.method as IMethod, params.params)) ?? false

      auditSigningRequest({
        keyName,
        clientPubkey: params.pubkey,
        method: params.method,
        eventKind,
        allowed: isAllowed,
        reason: isAllowed ? 'Allowed via ACL' : 'Blocked by ACL',
        timestamp: new Date().toISOString()
      })

      if (isAllowed) {
        log.signing(`✅ Allowed via ACL: ${keyName} for ${params.method}`)
        return true
      }

      log.signing(`❌ Blocked by ACL: ${keyName} for ${params.method} (device: ${params.pubkey.slice(0, 8)}...)`)
      return false
    } catch (err: any) {
      logError(`ACL check failed for ${keyName} / ${params.method}: ${err?.message ?? err}`)
      auditSigningRequest({
        keyName,
        clientPubkey: params.pubkey,
        method: params.method,
        eventKind,
        allowed: false,
        reason: `ACL check failed: ${err?.message ?? err}`,
        timestamp: new Date().toISOString()
      })
      return false
    }
  }
}

export default async function run(config: DaemonConfig) {
  const daemon = new Daemon(config)
  await daemon.start()
}

export class Daemon {
  public ndk: NDK
  public config: DaemonConfig
  public adminInterface: AdminInterface
  public httpServer: any
  public isReady: boolean = false
  public platformId: string = ''
  public platformServiceEntryId: string | null = null

  constructor(config: DaemonConfig) {
    this.config = config
    const registrarUid = process.env.REGISTRAR_UID
    const registrarEcdhPubkey = process.env.REGISTRAR_ECDH_PUBKEY
    const authorizerUid = process.env.AUTHORIZER_UID
    const authorizerEcdhPubkey = process.env.AUTHORIZER_ECDH_PUBKEY
    this.adminInterface = new AdminInterface(
      {
        ...config.admin,
        registrarUid,
        registrarEcdhPubkey,
        authorizerUid,
        authorizerEcdhPubkey
      },
      config
    )

    this.adminInterface.loadKey = this.loadKey.bind(this)
    this.adminInterface.getPlatformServiceEntryId = () => this.platformServiceEntryId

    this.ndk = new NDK({
      explicitRelayUrls: config.nostr.relays,
      enableOutboxModel: false,
      autoDeviceDiscovery: false,
      autoFetchUserMutelist: false,
      autoConnectUserRelays: false,
      cacheAdapter: undefined
    })

    // Assign a signer to the NDK instance so it can handle NIP-42 AUTH challenges
    // Using SIGNER_DAEMON_KEY + SIGNER_DAEMON_ECDH_KEY for the daemon's own connection authentication
    log.daemon(`SIGNER_DAEMON_KEY: ${process.env.SIGNER_DAEMON_KEY ? 'present' : 'missing'}`)
    if (process.env.SIGNER_DAEMON_KEY) {
      log.daemon('Daemon NDK Signer configured with SIGNER_DAEMON_KEY')
      const daemonSigner = new NDKMlDsaSigner(process.env.SIGNER_DAEMON_KEY)
      if (!process.env.SIGNER_DAEMON_ECDH_KEY) {
        throw new Error('SIGNER_DAEMON_ECDH_KEY environment variable not set')
      }
      const daemonEcdhSigner = new NDKPrivateKeySigner(process.env.SIGNER_DAEMON_ECDH_KEY)
      this.ndk.signer = new NDKTransportCredential(daemonSigner, daemonEcdhSigner, this.ndk)
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

  async fetchPlatformChain(platformId: string): Promise<any[]> {
    return new Promise<any[]>((resolve, reject) => {
      const events: any[] = []
      const relaySet = NDKRelaySet.fromRelayUrls(this.config.nostr.relays, this.ndk)

      const timeout = setTimeout(() => {
        if (events.length === 0) {
          reject(new Error(`fetchPlatformChain timed out after 10000ms with no events from relay for platform id ${platformId}`))
        } else {
          resolve(events)
        }
      }, 10000)

      const sub = this.ndk.subscribe(
        { kinds: [297], authors: [platformId] },
        { closeOnEose: true, relaySet }
      )
      sub.on('event', (ev: NDKEvent) => {
        events.push({
          id: ev.id,
          uid: (ev as any).uid ?? ev.pubkey,
          created_at: ev.created_at,
          kind: ev.kind,
          variant: ev.tags?.find((t) => t[0] === 'v')?.[1],
          kid: (ev as any).kid,
          key: (ev as any).key,
          tags: ev.tags,
          content: ev.content,
          sig: ev.sig
        })
      })
      sub.on('eose', () => {
        clearTimeout(timeout)
        if (events.length === 0) {
          reject(new Error(`fetchPlatformChain received EOSE with no events from relay for platform id ${platformId}`))
        } else {
          resolve(events)
        }
      })
    })
  }

  async startKeys() {
    const identityRows = await prisma.key.findMany({
      where: {
        status: 'ACTIVE',
        role: 'identity'
      },
      select: { keyName: true }
    })

    log.keys(`Starting ${identityRows.length} identity key families from database`)

    for (const row of identityRows) {
      try {
        const family = await resolveKeyFamily(row.keyName)
        if (family) {
          log.keys(`Starting key family for: ${row.keyName}`)
          await this.startFamily(family)
        } else {
          logError('keys', `Could not resolve key family for: ${row.keyName}`)
        }
      } catch (e: any) {
        logError('keys', `Failed to start key family ${row.keyName}`, e)
      }
    }
  }

  async start() {
    // Validate daemon configuration against legacy shapes
    if (this.config && isLegacyConfigFile(this.config)) {
      logError('daemon', 'FATAL: Daemon configuration contains legacy key material (admin.key / keys.admin / npubs).')
      process.exit(1)
    }

    // Validate daemon environment variables against SSOT requirements
    const envResult = validateDaemonEnvironment(process.env)
    if (!envResult.valid) {
      logError('daemon', envResult.error!)
      process.exit(1)
    }

    logStartup('SIGNER_KEK validated')
    logStartup('SIGNER_DAEMON_KEY validated')
    logStartup('SIGNER_DAEMON_ECDH_KEY validated')
    if (process.env.SIGNER_UID) {
      logStartup('SIGNER_UID verified against derived daemon key')
    }

    const daemonKey = process.env.SIGNER_DAEMON_KEY!
    const daemonPubkey = publicKeyFromSecret('ml-dsa-44', daemonKey)
    const daemonKeyHash = bytesToHex(sha256(daemonPubkey))
    const platformId = process.env.VERITY_PLATFORM_ID!
    this.platformId = platformId
    logStartup(`Platform ID configured: ${this.platformId.substring(0, 16)}...`)

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
        logStartup(`nsecBunker connected and ready: ${user?.pubkey?.substring(0, 16) || 'unknown identity'} after ${attempts} attempts`)
      } catch (e: any) {
        logError('daemon', `Initial connection failed: ${e.message}`)
        log.daemon(`Retrying in ${RETRY_DELAY_MS}ms...`)
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS))
      }
    }

    // Wait for relay authentication to complete before querying platform chain
    const NDK_RELAY_STATUS_AUTHENTICATED = 8
    const relays = Array.from(this.ndk.pool.relays.values()) as any[]
    for (const poolRelay of relays) {
      let authAttempts = 0
      while (poolRelay && poolRelay.status < NDK_RELAY_STATUS_AUTHENTICATED && authAttempts < 50) {
        await new Promise((resolve) => setTimeout(resolve, 100))
        authAttempts++
      }
    }

    // Platform chain verification with retry loop (matching ML-DSA daemonKeyHash)
    let platformVerified = false
    let platformAttempts = 0

    while (!platformVerified) {
      platformAttempts++
      log.daemon(`Verifying platform chain (attempt ${platformAttempts})...`)
      try {
        const events = await this.fetchPlatformChain(platformId)
        const verification = verifyPlatformChain(events, platformId)
        if (!verification.verified) {
          throw new Error(verification.error || 'platform chain verification failed')
        }

        const serviceEntry = findServiceEntry(events, daemonKeyHash)
        if (!serviceEntry) {
          throw new Error(`daemon service entry missing for key hash ${daemonKeyHash}`)
        }

        this.platformServiceEntryId = serviceEntry.id
        platformVerified = true
        logStartup(`✅ Platform chain verified: ${events.length} entries, daemon service entry ${serviceEntry.id.substring(0, 16)}...`)

        checkpointService.broadcast('signer.platform_chain.verified', {
          platformId: platformId.substring(0, 16),
          serviceEntryId: serviceEntry.id.substring(0, 16)
        })
      } catch (e: any) {
        logError('daemon', `Platform chain verification attempt ${platformAttempts} failed: ${e.message}`)
        log.daemon(`Retrying platform chain verification in ${RETRY_DELAY_MS}ms...`)
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
   * Start a key family backend
   */
  async startFamily(family: KeyFamily) {
    const cb = signingAuthorizationCallback(family.identity.keyName)
    const backend = new Backend(this.ndk, family, cb, this.config)
    await backend.start()
  }

  /**
   * Load and start a key
   */
  async loadKey(name: string, rawHex: string, algorithm: string = 'ml-dsa-44') {
    const family = await resolveKeyFamily(name)
    if (family) {
      await this.startFamily(family)
    } else {
      const cb = signingAuthorizationCallback(name)
      const derivedPubkey = bytesToHex(publicKeyFromSecret(algorithm, rawHex))
      const backend = new Backend(
        this.ndk,
        {
          identity: {
            keyName: name,
            pubkey: derivedPubkey,
            privateKeyHex: rawHex,
            algorithm
          }
        },
        cb,
        this.config
      )
      await backend.start()
    }
  }
}
