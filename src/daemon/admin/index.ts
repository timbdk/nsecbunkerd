import NDK, {
  NDKEvent,
  NDKKind,
  NDKMlDsaSigner,
  NDKPrivateKeySigner,
  NDKRelayAuthPolicies,
  NDKRpcRequest,
  NDKRpcResponse,
  NDKSigner,
  NDKTransportCredential,
  NDKUser,
  NostrEvent,
  NDKNostrRpc
} from '@nostr-dev-kit/ndk'
import {
  KIND_ADMIN_COMMAND, KIND_ADMIN_RESPONSE,
  AdminCommandDefinition, identityIdFromPublicKey
} from 'verity-event-data-module'

export interface ValidatedRpcRequest<T> extends NDKRpcRequest {
  validatedParams: T
}
import { IConfig } from '../../config/index.js'
import { log, logError } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'
import createAccount from './commands/create_account.js'
import authorizeClient from './commands/authorize_client.js'
import ping from './commands/ping.js'
import revokeClient from './commands/revoke_client.js'
import revokeUser from './commands/revoke_user.js'
import renameAccount from './commands/rename_account.js'

export type IAdminOpts = {
  allowedUids?: string[]
  registrarUid?: string
  registrarEcdhPubkey?: string
  authorizerUid?: string
  authorizerEcdhPubkey?: string
  adminRelays: string[]
}

class AdminInterface {
  private allowedUids: string[]
  public ndk: NDK
  private signerUser?: NDKUser
  private rpcSigner: NDKSigner
  readonly rpc: NDKNostrRpc
  public loadKey?: (keyName: string, rawHex: string, algorithm?: string) => void
  public getPlatformServiceEntryId?: () => string | null

  public readonly opts: IAdminOpts
  private configData: IConfig

  constructor(opts: IAdminOpts, configData: IConfig) {
    log.admin('AdminInterface Constructor Called')
    this.opts = opts
    this.configData = configData
    this.allowedUids = opts.allowedUids || []

    const daemonKey = process.env.SIGNER_DAEMON_KEY
    if (!daemonKey) {
      throw new Error('SIGNER_DAEMON_KEY environment variable not set')
    }
    const daemonSigner = new NDKMlDsaSigner(daemonKey)
    const daemonEcdhKey = process.env.SIGNER_DAEMON_ECDH_KEY
    if (!daemonEcdhKey) {
      throw new Error('SIGNER_DAEMON_ECDH_KEY environment variable not set')
    }
    const daemonEcdhSigner = new NDKPrivateKeySigner(daemonEcdhKey)
    const credential = new NDKTransportCredential(daemonSigner, daemonEcdhSigner)

    this.rpcSigner = credential

    this.ndk = new NDK({
      explicitRelayUrls: opts.adminRelays,
      enableOutboxModel: false,
      autoConnectUserRelays: false,
      signer: credential
    })
    // Enable NIP-42 auto-auth for admin relay connections
    this.ndk.relayAuthDefaultPolicy = NDKRelayAuthPolicies.signIn({ ndk: this.ndk })
    this.rpcSigner.user().then((user: NDKUser) => {
      this.validateAdminIdentity(user)
      this.signerUser = user
      this.connect()
    })

    this.rpc = new NDKNostrRpc(this.ndk, this.rpcSigner, log.admin)
    this.rpc.adminEcdhPubkeys = new Map<string, string>()
    const regUid = opts.registrarUid || process.env.REGISTRAR_UID
    const regEcdh = opts.registrarEcdhPubkey || process.env.REGISTRAR_ECDH_PUBKEY
    if (regUid && regEcdh) {
      this.rpc.adminEcdhPubkeys.set(regUid, regEcdh)
    }
    const authUid = opts.authorizerUid || process.env.AUTHORIZER_UID
    const authEcdh = opts.authorizerEcdhPubkey || process.env.AUTHORIZER_ECDH_PUBKEY
    if (authUid && authEcdh) {
      this.rpc.adminEcdhPubkeys.set(authUid, authEcdh)
    }
  }

  public async config(): Promise<IConfig> {
    return this.configData
  }

  public async uid() {
    return identityIdFromPublicKey((await this.rpcSigner.user()).pubkey)
  }

  private connect() {
    if (this.allowedUids.length <= 0 && !this.opts.registrarUid) {
      log.admin(`❌ Admin interface not starting because no admin uids/registrarUid were provided`)
      return
    }

    this.ndk.pool.on('relay:connect', (r) => log.admin(`✅ nsecBunker Admin Interface ready (connected to ${r.url})`))
    this.ndk.pool.on('relay:disconnect', (r) => log.admin(`❌ admin disconnected from ${r.url}`))
    
    this.ndk
      .connect(2500)
      .then(() => {
        // Subscribe only to admin commands. Responses use KIND_ADMIN_RESPONSE
        // and are published by us, not consumed.
        const signerUid = identityIdFromPublicKey(this.signerUser!.pubkey)
        this.rpc.subscribe({
          kinds: [KIND_ADMIN_COMMAND as number],
          '#p': [signerUid]
        })

        this.rpc.on('request', (req) => this.handleRequest(req))
      })
      .catch((err) => {
        logError('admin', 'admin connection failed', err)
      })
  }

  private async handleRequest(req: NDKRpcRequest) {
    try {
      checkpointService.broadcast('signer.event.received', {
        method: req.method,
        id: req.id?.substring(0, 16),
        from: req.pubkey?.substring(0, 16),
      })

      await this.validateRequest(req)

      checkpointService.broadcast('signer.event.validated', {
        method: req.method,
        id: req.id?.substring(0, 16),
      })

      // Validate and convert positional params to named object using EDM wire format
      let validatedReq = req as ValidatedRpcRequest<any>
      if (AdminCommandDefinition.rpcPayloads?.[req.method]?.fieldOrder) {
        try {
          const wire = AdminCommandDefinition.wire(req.method)
          validatedReq.validatedParams = wire.fromPositional(req.params as (string | undefined)[])
        } catch (e: any) {
          log.admin(`⛔ Invalid params for ${req.method}: ${e.message}`)
          return this.rpc.sendResponse(
            req.id, req.pubkey, 'error', KIND_ADMIN_RESPONSE,
            `Invalid params for ${req.method}: ${e.message}`
          )
        }
      }

      switch (req.method) {
        case 'create_account':
          await createAccount(this, validatedReq)
          break
        case 'authorize_client':
          await authorizeClient(this, validatedReq)
          break
        case 'revoke_client':
          await revokeClient(this, validatedReq)
          break
        case 'revoke_user':
          await revokeUser(this, validatedReq)
          break
        case 'ping':
          await ping(this, validatedReq)
          break
        case 'rename_account': {
          await renameAccount(this, validatedReq)
          break
        }




        default:
          log.admin(`Unknown method ${req.method}`)
          // Admin responses use KIND_ADMIN_RESPONSE from event-data-module (SSOT)
          return this.rpc.sendResponse(req.id, req.pubkey, JSON.stringify(['error', `Unknown method ${req.method}`]), KIND_ADMIN_RESPONSE)
      }
    } catch (err: any) {
      log.admin(`Error handling request ${req.method}: ${err?.message ?? err}`, req.params)
      // Admin responses use KIND_ADMIN_RESPONSE from event-data-module (SSOT)
      return this.rpc.sendResponse(req.id, req.pubkey, 'error', KIND_ADMIN_RESPONSE, err?.message)
    }
  }

  private async validateRequest(req: NDKRpcRequest): Promise<void> {
    if (!req.event || typeof req.event.verifySignature !== 'function' || !req.event.verifySignature(false)) {
      throw new Error('Event signature verification failed')
    }

    const callerKeys = new Set<string>()
    if (req.pubkey) {
      callerKeys.add(req.pubkey)
      try {
        callerKeys.add(identityIdFromPublicKey(req.pubkey))
      } catch {
        // ignore if not valid key material
      }
    }
    const eventUid = (req.event as any)?.uid
    if (eventUid) {
      callerKeys.add(eventUid)
    }
    const eventPubkey = req.event?.pubkey
    if (eventPubkey) {
      callerKeys.add(eventPubkey)
      try {
        callerKeys.add(identityIdFromPublicKey(eventPubkey))
      } catch {
        // ignore
      }
    }

    const registrarKeys = new Set<string>()
    if (this.opts?.registrarUid) {
      registrarKeys.add(this.opts.registrarUid)
    }

    const isRegistrar = Array.from(callerKeys).some((k) => registrarKeys.has(k))
    if (registrarKeys.size > 0 && isRegistrar) {
      const payloads = AdminCommandDefinition.describe().rpcPayloads
      const allowedMethods = payloads 
        ? Object.entries(payloads)
            .filter(([, def]) => def.status === 'implemented')
            .map(([name]) => name)
        : []
      if (allowedMethods.includes(req.method)) {
        log.admin(`✅ Allowing ${req.method} from Restricted Registrar: ${this.opts?.registrarUid}`)
        return
      } else {
        log.admin(`⛔ Denying ${req.method} from Restricted Registrar: ${this.opts?.registrarUid}`)
        throw new Error('Registrar is only allowed to call: ' + allowedMethods.join(', '))
      }
    }

    if (this.allowedUids.length > 0) {
      const allowed = new Set<string>(this.allowedUids)
      const isAllowedAdmin = Array.from(callerKeys).some((k) => allowed.has(k))
      if (!isAllowedAdmin) {
        throw new Error('You are not designated to administrate this bunker')
      }
      return
    }

    throw new Error('You are not designated to administrate this bunker')
  }

  /**
   * Validates that the derived admin pubkey matches SIGNER_UID if set.
   */
  private validateAdminIdentity(user: NDKUser) {
    const derivedPubkey = user.pubkey
    const derivedUid = identityIdFromPublicKey(derivedPubkey)
    log.admin(`🔑 Admin interface identity: ${derivedUid} (${derivedPubkey.substring(0, 16)}...)`)

    const signerUid = process.env.SIGNER_UID
    if (signerUid) {
      if (signerUid !== derivedUid) {
        log.admin(`❌ FATAL: SIGNER_UID mismatch!`)
        log.admin(`   Expected (SIGNER_UID): ${signerUid}`)
        log.admin(`   Derived (daemon key):   ${derivedUid}`)
        process.exit(1)
      }
      log.admin(`✅ SIGNER_UID matches derived daemon identity`)
    }
  }
}

export default AdminInterface
