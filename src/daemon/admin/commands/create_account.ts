import { NDKKind, NDKPrivateKeySigner, NDKRpcRequest, NDKUser } from '@nostr-dev-kit/ndk'
import AdminInterface from '..'
import { allowAllRequestsFromKey } from '../../lib/acl/index.js'
import { publishUsernameEvent } from '../../lib/username-event.js'
import prisma from '../../../db.js'
import { log } from '../../../lib/logger.js'
import { encryptPrivateKey, storeKey, hexToNsec, markKeyBackedUp } from '../../../services/KeyService.js'
import { backupKey } from '../../../services/BackupService.js'
import { checkpointService } from '../../../services/CheckpointService.js'


export async function validate(username: string, domain: string) {
  if (!username) {
    throw new Error('username is required')
  }

  // Check if username already exists in database
  const keyName = `${username}@${domain}`
  const existingKey = await prisma.key.findFirst({
    where: { keyName, status: 'ACTIVE' }
  })

  if (existingKey) {
    throw new Error('username already exists')
  }
}

const RESERVED_USERNAMES = ['admin', 'root', '_', 'administrator', '__']

async function validateUsername(username: string | undefined) {
  if (!username || username.length === 0) {
    username = Math.random().toString(36).substring(2, 15)
  }

  if (RESERVED_USERNAMES.includes(username)) {
    throw new Error('username not available')
  }

  return username
}

export default async function createAccount(admin: AdminInterface, req: NDKRpcRequest) {
  // params: [username, domain, email?, clientPubkey?, correlationId?]
  let [username, domain, email, clientPubkey, correlationId] = req.params as [string?, string?, string?, string?, string?]
  const fallbackDomain = 'verity.local' // Or get from config but we don't validate against hardcoded config.domains anymore

  if (!domain || domain.length === 0) domain = fallbackDomain

  log.admin(`[${correlationId?.slice(0, 8) || 'no-corr'}] create_account request from ${req.pubkey.slice(0, 16)}...`)

  try {
    username = await validateUsername(username)
  } catch (e: any) {
    const originalKind = req.event.kind!
    log.admin(`[${correlationId?.slice(0, 8) || 'no-corr'}] create_account validation failed: ${e.message}`)
    admin.rpc.sendResponse(req.id, req.pubkey, 'error', originalKind, e.message)
    return
  }

  return createAccountReal(admin, req, username, domain, email, clientPubkey)
}

export async function createAccountReal(
  admin: AdminInterface,
  req: NDKRpcRequest,
  username: string,
  domain: string,
  email?: string,
  clientPubkey?: string
): Promise<void> {
  const { auditService } = await import('../../../services/AuditService.js')
  const scope = auditService.createScope(req.id, 'create_account')

  scope.logReceived({
    clientPubkey,
    requestEventId: req.event.id,
    userIdentifier: `${username}@${domain}`,
    details: { username, domain, email }
  })

  try {
    log.admin(`[${req.id}] create_account request from ${clientPubkey?.slice(0, 16) || 'unknown'}...`)
    log.admin(`[${req.id}] Creating account for ${username}@${domain}`)

    try {
      await validate(username, domain)
    } catch (e: any) {
      if (e.message === 'username already exists') {
        log.admin('username already exists, implementing idempotency')
        const keyName = `${username}@${domain}`
        const existingKey = await prisma.key.findFirst({
          where: { keyName, status: 'ACTIVE' },
          select: { pubkey: true }
        })
        if (existingKey) {
          log.admin(`Found existing pubkey ${existingKey.pubkey} for ${username}`)
          await grantPermissions(req, keyName, clientPubkey)
          log.admin('permissions re-granted for existing user')
          return admin.rpc.sendResponse(req.id, req.pubkey, existingKey.pubkey, NDKKind.NostrConnectAdmin)
        }
      }
      throw e
    }

    const nip05 = `${username}@${domain}`
    const key = NDKPrivateKeySigner.generate()
    const generatedUser = await key.user()

    log.admin(`Created user ${generatedUser.npub} for ${nip05}`)

    const keyName = nip05
    const privateKeyHex = key.privateKey!
    const nsec = hexToNsec(privateKeyHex)

    log.admin(`Encrypting key for ${keyName}`)
    const encryptedData = encryptPrivateKey(privateKeyHex, keyName)

    log.admin(`Backing up key for ${keyName}`)
    const backupResult = await backupKey(keyName, encryptedData, generatedUser.pubkey)
    if (!backupResult.success) {
      throw new Error(`Backup failed for ${keyName}: ${backupResult.error}`)
    }

    log.admin(`Storing key locally for ${keyName}`)
    await storeKey(keyName, privateKeyHex, generatedUser.pubkey)
    await markKeyBackedUp(keyName)

    await admin.loadNsec!(keyName, nsec)

    const currentConfig = await admin.config()
    await publishUsernameEvent(key, username, generatedUser.pubkey, currentConfig.nostr.relays)
    log.admin(`[${req.id}] Kind 415 published for ${username}`)

    await grantPermissions(req, keyName, clientPubkey)

    checkpointService.broadcast('signer.command.completed', {
      method: 'create_account',
      keyName,
      pubkey: generatedUser.pubkey?.substring(0, 16),
    })

    scope.logResponse({
      userPubkey: generatedUser.pubkey,
      userIdentifier: keyName,
      responseEventId: undefined,
      clientPubkey: clientPubkey || req.pubkey
    })

    checkpointService.broadcast('signer.response.sent', {
      method: 'create_account',
    })

    return admin.rpc.sendResponse(req.id, req.pubkey, generatedUser.pubkey, NDKKind.NostrConnectAdmin)
  } catch (e: any) {
    log.admin(`error creating account: ${e.message}`)
    scope.logError(e, { username, domain })
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnectAdmin, e.message)
  }
}

async function grantPermissions(req: NDKRpcRequest, keyName: string, clientPubkey?: string) {
  await allowAllRequestsFromKey(req.pubkey, keyName, 'connect', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'sign_event', undefined, 'registrar', { kind: null })
  await allowAllRequestsFromKey(req.pubkey, keyName, 'encrypt', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'decrypt', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'switch_relays', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'get_public_key', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'ping', undefined, 'registrar')

  if (clientPubkey) {
    await allowAllRequestsFromKey(clientPubkey, keyName, 'connect', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'sign_event', undefined, 'client', { kind: null })
    await allowAllRequestsFromKey(clientPubkey, keyName, 'encrypt', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'decrypt', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'switch_relays', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'get_public_key', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'ping', undefined, 'client')
  }
}
