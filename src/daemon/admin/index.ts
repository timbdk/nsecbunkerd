import NDK, {
  NDKEvent,
  NDKKind,
  NDKPrivateKeySigner,
  NDKRelayAuthPolicies,
  NDKRpcRequest,
  NDKRpcResponse,
  NDKUser,
  NostrEvent,
  NDKNostrRpc
} from '@nostr-dev-kit/ndk'
import { nip19 } from 'nostr-tools'
import {
  KIND_ADMIN_COMMAND, KIND_ADMIN_RESPONSE,
  AdminCommandDefinition
} from 'verity-event-validation-module'

export interface ValidatedRpcRequest<T> extends NDKRpcRequest {
  validatedParams: T
}
import { Key, Session } from '../run.js'
import { allowAllRequestsFromKey } from '../lib/acl/index.js'
import prisma from '../../db.js'
import createAccount from './commands/create_account.js'
import authorizeClient from './commands/authorize_client.js'
import ping from './commands/ping.js'
import revokeClient from './commands/revoke_client.js'
import revokeUser from './commands/revoke_user.js'
import renameAccount from './commands/rename_account.js'
import { validateRequestFromAdmin } from './validations/request-from-admin.js'
import { IConfig } from '../../config/index.js'
import { log, logError } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

export type IAdminOpts = {
  npubs: string[]
  registrarNpub?: string
  adminRelays: string[]
  key: string
}


class AdminInterface {
  private npubs: string[]
  private ndk: NDK
  private signerUser?: NDKUser
  readonly rpc: NDKNostrRpc
  public loadNsec?: (keyName: string, nsec: string) => void

  public readonly opts: IAdminOpts
  private configData: IConfig

  constructor(opts: IAdminOpts, configData: IConfig) {
    log.admin('AdminInterface Constructor Called')
    this.opts = opts
    this.configData = configData
    this.npubs = opts.npubs || []
    this.ndk = new NDK({
      explicitRelayUrls: opts.adminRelays,
      signer: new NDKPrivateKeySigner(opts.key)
    })
    // Enable NIP-42 auto-auth for admin relay connections
    this.ndk.relayAuthDefaultPolicy = NDKRelayAuthPolicies.signIn({ ndk: this.ndk })
    this.ndk.signer?.user().then((user: NDKUser) => {
      this.signerUser = user
      this.validateAdminIdentity(user)
      this.connect()
    })

    this.rpc = new NDKNostrRpc(this.ndk, this.ndk.signer!, log.admin)
  }

  public async config(): Promise<IConfig> {
    return this.configData
  }

  public async npub() {
    return (await this.ndk.signer?.user())!.npub
  }

  private connect() {
    if (this.npubs.length <= 0 && !this.opts.registrarNpub) {
      log.admin(`❌ Admin interface not starting because no admin npubs were provided`)
      return
    }

    this.ndk.pool.on('relay:connect', (r) => log.admin(`✅ nsecBunker Admin Interface ready (connected to ${r.url})`))
    this.ndk.pool.on('relay:disconnect', (r) => log.admin(`❌ admin disconnected from ${r.url}`))
    
    this.ndk
      .connect(2500)
      .then(() => {
        // Subscribe only to admin commands. Responses use KIND_ADMIN_RESPONSE
        // and are published by us, not consumed.
        this.rpc.subscribe({
          kinds: [KIND_ADMIN_COMMAND as number],
          '#p': [this.signerUser!.pubkey]
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

      // Validate and convert positional params to named object using EVM wire format
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
          // Admin responses use KIND_ADMIN_RESPONSE from event-validation-module (SSOT)
          return this.rpc.sendResponse(req.id, req.pubkey, JSON.stringify(['error', `Unknown method ${req.method}`]), KIND_ADMIN_RESPONSE)
      }
    } catch (err: any) {
      log.admin(`Error handling request ${req.method}: ${err?.message ?? err}`, req.params)
      // Admin responses use KIND_ADMIN_RESPONSE from event-validation-module (SSOT)
      return this.rpc.sendResponse(req.id, req.pubkey, 'error', KIND_ADMIN_RESPONSE, err?.message)
    }
  }

  private async validateRequest(req: NDKRpcRequest): Promise<void> {
    const registrarNpub = this.opts?.registrarNpub
    if (registrarNpub) {
      const registrarPubkey = new NDKUser({ npub: registrarNpub }).pubkey
      if (req.pubkey === registrarPubkey) {
        const payloads = AdminCommandDefinition.describe().rpcPayloads
        const allowedMethods = payloads 
          ? Object.entries(payloads)
              .filter(([, def]) => def.status === 'implemented')
              .map(([name]) => name)
          : []
        if (allowedMethods.includes(req.method)) {
          log.admin(`✅ Allowing ${req.method} from Restricted Registrar: ${registrarNpub}`)
          return
        } else {
          log.admin(`⛔ Denying ${req.method} from Restricted Registrar: ${registrarNpub}`)
          throw new Error('Registrar is only allowed to call: ' + allowedMethods.join(', '))
        }
      }
    }

    if (!(await validateRequestFromAdmin(req, this.npubs))) {
      throw new Error('You are not designated to administrate this bunker')
    }
  }

  /**
   * Validates that the derived admin pubkey matches SIGNER_NPUB if set.
   * Prevents configuration drift between nsecbunker.json and environment variables.
   */
  private validateAdminIdentity(user: NDKUser) {
    const derivedPubkey = user.pubkey
    const derivedNpub = nip19.npubEncode(derivedPubkey)
    log.admin(`🔑 Admin interface identity: ${derivedNpub} (${derivedPubkey.substring(0, 16)}...)`)

    const signerNpub = process.env.SIGNER_NPUB
    if (signerNpub) {
      try {
        const { data: expectedPubkey } = nip19.decode(signerNpub) as { data: string }
        if (expectedPubkey !== derivedPubkey) {
          log.admin(`❌ FATAL: SIGNER_NPUB mismatch!`)
          log.admin(`   Expected (SIGNER_NPUB): ${expectedPubkey.substring(0, 16)}...`)
          log.admin(`   Derived (admin.key):    ${derivedPubkey.substring(0, 16)}...`)
          log.admin(`   The admin.key in nsecbunker.json does not match SIGNER_NPUB.`)
          process.exit(1)
        }
        log.admin(`✅ SIGNER_NPUB matches derived admin pubkey`)
      } catch (e: any) {
        log.admin(`❌ FATAL: Invalid SIGNER_NPUB format: ${e.message}`)
        process.exit(1)
      }
    }
  }
}

export default AdminInterface
