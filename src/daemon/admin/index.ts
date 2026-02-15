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
import createDebug from 'debug'
import { Key, KeyUser } from '../run'
import { allowAllRequestsFromKey } from '../lib/acl/index.js'
import prisma from '../../db'
import createAccount from './commands/create_account'
import authorizeClient from './commands/authorize_client'
import ping from './commands/ping.js'
import createNewKey from './commands/create_new_key'
import revokeClient from './commands/revoke_client'
import fs from 'fs'
import { validateRequestFromAdmin } from './validations/request-from-admin'
import { dmUser } from '../../utils/dm-user'
import { IConfig, getCurrentConfig } from '../../config'
import path from 'path'

import { log } from '../../lib/logger.js'

// import { log } from '../../lib/logger.js';

// const debug = createDebug("nsecbunker:admin"); // Replaced by log.admin // Replaced by log.admin

export type IAdminOpts = {
  npubs: string[]
  registrarNpub?: string
  adminRelays: string[]
  key: string
  notifyAdminsOnBoot?: boolean
}

// TODO: Move to configuration
const allowNewKeys = true

/**
 * This class represents the admin interface for the nsecbunker daemon.
 *
 * It provides an interface for a UI to manage the daemon over nostr.
 */
class AdminInterface {
  private npubs: string[]
  private ndk: NDK
  private signerUser?: NDKUser
  readonly rpc: NDKNostrRpc
  readonly configFile: string
  public getKeys?: () => Promise<Key[]>
  public getKeyUsers?: (req: NDKRpcRequest) => Promise<KeyUser[]>
  public unlockKey?: (keyName: string, passphrase: string) => Promise<boolean>
  public loadNsec?: (keyName: string, nsec: string) => void

  public readonly opts: IAdminOpts

  private configData?: IConfig

  constructor(opts: IAdminOpts, configFile: string, configData?: IConfig) {
    console.log('DEBUG: AdminInterface Constructor Called - CODE IS UPDATING')
    this.opts = opts
    this.configFile = configFile
    this.configData = configData
    this.npubs = opts.npubs || []
    this.ndk = new NDK({
      explicitRelayUrls: opts.adminRelays,
      signer: new NDKPrivateKeySigner(opts.key)
    })
    this.ndk.signer?.user().then((user: NDKUser) => {
      let connectionString = `bunker://${user.npub}`

      if (opts.adminRelays.length > 0) {
        connectionString += '@' + encodeURIComponent(`${opts.adminRelays.join(',').replace(/wss:\/\//g, '')}`)
      }

      console.log(`\n\nnsecBunker connection string:\n\n${connectionString}\n\n`)

      // write connection string to connection.txt
      const configFolder = path.dirname(configFile)
      try {
        fs.writeFileSync(path.join(configFolder, 'connection.txt'), connectionString)
      } catch (e) {
        /* ignore read-only */
      }

      this.signerUser = user

      this.connect()

      this.config().then((config) => {
        if (config.admin?.notifyAdminsOnBoot) {
          this.notifyAdminsOfNewConnection(connectionString)
        }
      })
    })

    this.rpc = new NDKNostrRpc(this.ndk, this.ndk.signer!, log.admin)
  }

  public async config(): Promise<IConfig> {
    if (this.configData) return this.configData
    return getCurrentConfig(this.configFile)
  }

  private async notifyAdminsOfNewConnection(connectionString: string) {
    // Use the already-configured adminRelays instead of hardcoded external relays
    if (!this.npubs || this.npubs.length === 0) {
      return
    }

    for (const npub of this.npubs) {
      dmUser(this.ndk, npub, `nsecBunker has started; use ${connectionString} to connect to it and unlock your key(s)`)
    }
  }

  /**
   * Get the npub of the admin interface.
   */
  public async npub() {
    return (await this.ndk.signer?.user())!.npub
  }

  private connect() {
    // Start admin interface if we have admin npubs OR a registrar npub
    if (this.npubs.length <= 0 && !this.opts.registrarNpub) {
      console.log(`❌ Admin interface not starting because no admin npubs were provided`)
      return
    }

    this.ndk.pool.on('relay:connect', (r) => console.log(`✅ nsecBunker Admin Interface ready (connected to ${r.url})`))
    this.ndk.pool.on('relay:disconnect', (r) => console.log(`❌ admin disconnected from ${r.url}`))
    this.ndk
      .connect(2500)
      .then(() => {
        // connect for whitelisted admins
        this.rpc.subscribe({
          kinds: [NDKKind.NostrConnect, 24134 as number],
          '#p': [this.signerUser!.pubkey]
        })

        this.rpc.on('request', (req) => this.handleRequest(req))

        pingOrDie(this.ndk)
      })
      .catch((err) => {
        console.log('❌ admin connection failed')
        console.error(err)
      })
  }

  private async handleRequest(req: NDKRpcRequest) {
    try {
      await this.validateRequest(req)

      switch (req.method) {
        // Core commands (used in production)
        case 'create_account':
          await createAccount(this, req)
          break
        case 'authorize_client':
          await authorizeClient(this, req)
          break
        case 'revoke_client':
          await revokeClient(this, req)
          break
        case 'ping':
          await ping(this, req)
          break

        // Query commands (used for admin/testing)
        case 'get_keys':
          await this.reqGetKeys(req)
          break
        case 'get_key_users':
          await this.reqGetKeyUsers(req)
          break
        case 'create_new_key':
          await createNewKey(this, req)
          break

        default:
          const originalKind = req.event.kind!
          console.log(`Unknown method ${req.method}`)
          return this.rpc.sendResponse(req.id, req.pubkey, JSON.stringify(['error', `Unknown method ${req.method}`]), originalKind)
      }
    } catch (err: any) {
      log.admin(`Error handling request ${req.method}: ${err?.message ?? err}`, req.params)
      return this.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnectAdmin, err?.message)
    }
  }

  private async validateRequest(req: NDKRpcRequest): Promise<void> {
    // Restricted Registrar Logic: can ONLY call create_account, authorize_user, revoke_user
    const registrarNpub = this.opts?.registrarNpub
    if (registrarNpub) {
      const registrarPubkey = new NDKUser({ npub: registrarNpub }).pubkey
      if (req.pubkey === registrarPubkey) {
        const allowedMethods = ['create_account', 'authorize_user', 'authorize_client', 'revoke_user', 'revoke_client']
        if (allowedMethods.includes(req.method)) {
          console.log(`✅ Allowing ${req.method} from Restricted Registrar: ${registrarNpub}`)
          return
        } else {
          console.warn(`⛔ Denying ${req.method} from Restricted Registrar: ${registrarNpub}`)
          throw new Error('Registrar is only allowed to call: ' + allowedMethods.join(', '))
        }
      }
    }
    // if this request is of type create_account, allow it
    // TODO: require some POW to prevent spam
    if (req.method === 'create_account' && allowNewKeys) {
      console.log(`allowing create_account request`)
      return
    }

    if (!(await validateRequestFromAdmin(req, this.npubs))) {
      throw new Error('You are not designated to administrate this bunker')
    }
  }

  /**
   * Command to list tokens
   */
  private async reqGetKeyTokens(req: NDKRpcRequest) {
    const keyName = req.params[0]
    const tokens = await prisma.token.findMany({
      where: { keyName },
      include: {
        policy: {
          include: {
            rules: true
          }
        },
        KeyUser: true
      }
    })

    const keys = await this.getKeys!()
    const key = keys.find((k) => k.name === keyName)

    if (!key || !key.npub) {
      return this.rpc.sendResponse(req.id, req.pubkey, JSON.stringify([]), 24134)
    }

    const npub = key.npub

    const result = JSON.stringify(
      tokens.map((t) => {
        return {
          id: t.id,
          key_name: t.keyName,
          client_name: t.clientName,
          token: [npub, t.token].join('#'),
          policy_id: t.policyId,
          policy_name: t.policy?.name,
          created_at: t.createdAt,
          updated_at: t.updatedAt,
          expires_at: t.expiresAt,
          redeemed_at: t.redeemedAt,
          redeemed_by: t.KeyUser?.description,
          time_until_expiration: t.expiresAt ? (t.expiresAt.getTime() - Date.now()) / 1000 : null
        }
      })
    )

    return this.rpc.sendResponse(req.id, req.pubkey, result, 24134)
  }

  /**
   * Command to list policies
   */
  private async reqListPolicies(req: NDKRpcRequest) {
    const policies = await prisma.policy.findMany({
      include: {
        rules: true
      }
    })

    const result = JSON.stringify(
      policies.map((p) => {
        return {
          id: p.id,
          name: p.name,
          description: p.description,
          created_at: p.createdAt,
          updated_at: p.updatedAt,
          expires_at: p.expiresAt,
          rules: p.rules.map((r) => {
            return {
              method: r.method,
              kind: r.kind,
              max_usage_count: r.maxUsageCount,
              current_usage_count: r.currentUsageCount
            }
          })
        }
      })
    )

    return this.rpc.sendResponse(req.id, req.pubkey, result, 24134)
  }

  /**
   * Command to fetch keys and their current state
   */
  private async reqGetKeys(req: NDKRpcRequest) {
    if (!this.getKeys) throw new Error('getKeys() not implemented')

    const result = JSON.stringify(await this.getKeys())
    const pubkey = req.pubkey

    return this.rpc.sendResponse(req.id, pubkey, result, 24134) // 24134
  }

  /**
   * Command to fetch users of a key
   */
  private async reqGetKeyUsers(req: NDKRpcRequest): Promise<void> {
    if (!this.getKeyUsers) throw new Error('getKeyUsers() not implemented')

    const result = JSON.stringify(await this.getKeyUsers(req))
    const pubkey = req.pubkey

    return this.rpc.sendResponse(req.id, pubkey, result, 24134) // 24134
  }

  /**
   * This function is called when a request is received from a remote user that needs
   * to be approved by the admin interface.
   *
   * @returns true if the request is approved, false if it is denied, undefined if it timedout
   */
  public async requestPermission(keyName: string, remotePubkey: string, method: string, param: any): Promise<boolean | undefined> {
    const keyUser = await prisma.keyUser.findUnique({
      where: {
        unique_key_user: {
          keyName,
          userPubkey: remotePubkey
        }
      }
    })

    console.trace({ method, param })

    if (method === 'sign_event') {
      const e = param.rawEvent()
      param = JSON.stringify(e)

      console.log(`👀 Event to be signed\n`, {
        kind: e.kind,
        content: e.content,
        tags: e.tags
      })
    }

    return new Promise((resolve, reject) => {
      console.log(`requesting permission for`, keyName)
      console.log(`remotePubkey`, remotePubkey)
      console.log(`method`, method)
      console.log(`param`, param)
      console.log(`keyUser`, keyUser)

      /**
       * If an admin doesn't respond within 10 seconds, report back to the user that the request timed out
       */
      setTimeout(() => {
        resolve(undefined)
      }, 10000)

      for (const npub of this.npubs) {
        const remoteUser = new NDKUser({ npub })
        console.log(`sending request to ${npub}`, remoteUser.pubkey)
        const params = JSON.stringify({
          keyName,
          remotePubkey,
          method,
          param,
          description: keyUser?.description
        })

        this.rpc.sendRequest(remoteUser.pubkey, 'acl', [params], 24134, (res: NDKRpcResponse) => {
          this.requestPermissionResponse(remotePubkey, keyName, method, param, resolve, res)
        })
      }
    })
  }

  public async requestPermissionResponse(
    remotePubkey: string,
    keyName: string,
    method: string,
    param: string,
    resolve: (value: boolean) => void,
    res: NDKRpcResponse
  ) {
    let resObj
    try {
      resObj = JSON.parse(res.result)
    } catch (e) {
      console.log('error parsing result', e)
      return
    }

    switch (resObj[0]) {
      case 'always': {
        allowAllRequestsFromKey(remotePubkey, keyName, method, param, resObj[1], resObj[2])
        resolve(true)
        break
      }
      case 'never': {
        console.log('not implemented')
        break
      }
      default:
        console.log('request result', res.result)
    }
  }
}

async function pingOrDie(ndk: NDK) {
  let deathTimer: NodeJS.Timeout | null = null

  function resetDeath() {
    if (deathTimer) clearTimeout(deathTimer)
    deathTimer = setTimeout(() => {
      console.log(`⚠️  No ping event received in 50 seconds. Connection may be degraded.`)
      // Monitoring only - no longer exits
    }, 50000)
  }

  const self = await ndk.signer!.user()
  const sub = ndk.subscribe({
    authors: [self.pubkey],
    kinds: [1], // Regular notes
    '#t': ['nsecbunker-ping'], // Filter by tag
    '#p': [self.pubkey]
  })
  sub.on('event', (event: NDKEvent) => {
    console.log(`🔔 Received ping event:`, event.created_at)
    resetDeath()
  })
  sub.start()

  resetDeath()

  setInterval(() => {
    const event = new NDKEvent(ndk, {
      kind: 1, // Regular note - won't trigger NIP-46 RPC handler
      tags: [
        ['p', self.pubkey],
        ['t', 'nsecbunker-ping']
      ],
      content: 'ping'
    } as NostrEvent)
    event
      .publish()
      .then(() => {
        console.log(`🔔 Sent ping event:`, event.created_at)
      })
      .catch((e: any) => {
        console.log(`⚠️  Failed to send ping event:`, e.message)
        // Monitoring only - no longer exits
      })
  }, 20000)
}

export default AdminInterface
