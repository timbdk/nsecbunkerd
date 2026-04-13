import NDK, {
  NDKEvent,
  NDKKind,
  NDKPrivateKeySigner,
  NDKRpcRequest,
  NDKRpcResponse,
  NDKUser,
  NostrEvent,
  NDKNostrRpc
} from '@nostr-dev-kit/ndk'
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
    this.ndk.signer?.user().then((user: NDKUser) => {
      this.signerUser = user
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
        this.rpc.subscribe({
          kinds: [NDKKind.NostrConnect, 24134 as number],
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

      switch (req.method) {
        case 'create_account':
          await createAccount(this, req)
          break
        case 'authorize_client':
          await authorizeClient(this, req)
          break
        case 'revoke_client':
          await revokeClient(this, req)
          break
        case 'revoke_user':
          await revokeUser(this, req)
          break
        case 'ping':
          await ping(this, req)
          break
        case 'rename_account': {
          const currentConfig = await this.config()
          const result = await renameAccount(currentConfig, req.params, req.pubkey, req.id)

          checkpointService.broadcast('signer.command.completed', {
            method: 'rename_account',
            id: req.id?.substring(0, 16),
          })

          checkpointService.broadcast('signer.response.sent', {
            method: 'rename_account',
          })

          return this.rpc.sendResponse(req.id, req.pubkey, result, NDKKind.NostrConnectAdmin)
        }

        default:
          const originalKind = req.event.kind!
          log.admin(`Unknown method ${req.method}`)
          return this.rpc.sendResponse(req.id, req.pubkey, JSON.stringify(['error', `Unknown method ${req.method}`]), originalKind)
      }
    } catch (err: any) {
      log.admin(`Error handling request ${req.method}: ${err?.message ?? err}`, req.params)
      return this.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnectAdmin, err?.message)
    }
  }

  private async validateRequest(req: NDKRpcRequest): Promise<void> {
    const registrarNpub = this.opts?.registrarNpub
    if (registrarNpub) {
      const registrarPubkey = new NDKUser({ npub: registrarNpub }).pubkey
      if (req.pubkey === registrarPubkey) {
        const allowedMethods = ['create_account', 'rename_account', 'authorize_client', 'revoke_user', 'revoke_client']
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
}

export default AdminInterface
