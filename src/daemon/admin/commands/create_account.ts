import { NDKMlDsaSigner, NDKPrivateKeySigner, NDKRpcRequest, NDKUser } from '@nostr-dev-kit/ndk'
import { KIND_ADMIN_RESPONSE, RESERVED_USERNAMES, identityIdFromPublicKey, keygen, type CreateAccountInput } from 'verity-event-data-module'
import { bytesToHex } from '@noble/hashes/utils.js'
import AdminInterface, { type ValidatedRpcRequest } from '../index.js'
import { allowAllRequestsFromKey } from '../../lib/acl/index.js'
import { publishUsernameEvent } from '../../lib/username-event.js'
import { queryCurrentIdentityEntry } from '../../lib/keychain-event.js'
import prisma from '../../../db.js'
import { log } from '../../../lib/logger.js'
import { encryptPrivateKey, storeKey, markKeyBackedUp, retrieveKey } from '../../../services/KeyService.js'
import { backupKey } from '../../../services/BackupService.js'
import { checkpointService } from '../../../services/CheckpointService.js'
import { auditService } from '../../../services/AuditService.js'


export async function validate(username: string) {
  if (!username) {
    throw new Error('username is required')
  }

  // Check if username already exists in database
  const existingKey = await prisma.key.findFirst({
    where: { keyName: username, status: 'ACTIVE' }
  })

  if (existingKey) {
    throw new Error('username already exists')
  }
}



async function validateUsername(username: string) {
  if (RESERVED_USERNAMES.has(username)) {
    throw new Error('username not available')
  }

  return username
}

export default async function handle(
  admin: AdminInterface,
  req: ValidatedRpcRequest<CreateAccountInput>
) {
  const input = req.validatedParams
  const scope = auditService.createScope(req.id, 'create_account')
  scope.logReceived({
    clientPubkey: req.pubkey,
    details: { ...req.params }
  })
  log.admin(`[${req.id}] create_account for ${req.pubkey}`)

  checkpointService.broadcast('signer.command.received', {
    method: 'create_account',
    clientPubkey: req.pubkey
  })

  const { username, clientPubkey, inviterPubkey } = input

  try {
    try {
      await validate(username)
    } catch (e: any) {
      if (e.message === 'username already exists') {
        log.admin('username already exists, implementing idempotency')
        const existingKey = await prisma.key.findFirst({
          where: { keyName: username, status: 'ACTIVE' }
        })
        if (existingKey) {
          log.admin(`Found existing pubkey ${existingKey.pubkey} for ${username}`)
          const existingPrivateKeyHex = await retrieveKey(username)
          if (existingPrivateKeyHex) {
            const existingSigner = new NDKMlDsaSigner(existingPrivateKeyHex)
            const currentConfig = await admin.config()
            const daemonServiceEntryId = admin.getPlatformServiceEntryId?.()
            if (!daemonServiceEntryId) {
              throw new Error('Signer daemon has no verified platformServiceEntryId')
            }
            const encRow = await prisma.key.findFirst({
              where: { parentKeyName: username, role: 'enc', status: 'ACTIVE' }
            })
            if (!encRow) {
              throw new Error(`Active encryption key missing for account: ${username}`)
            }
            // Idempotency: both publishGenesisEntry and publishUsernameEvent query first.
            // If a crash occurred between genesis and 415 publication, this branch self-heals
            // by publishing the missing Kind 415 with deterministic content and matching kid.
            const { publishGenesisEntry } = await import('../../lib/keychain-event.js')
            const genesisEntryId = await publishGenesisEntry(
              existingSigner,
              existingKey.pubkey,
              currentConfig.nostr.relays,
              daemonServiceEntryId,
              undefined,
              admin.ndk,
              encRow?.pubkey
            )
            await publishUsernameEvent(
              existingSigner,
              username,
              existingKey.pubkey,
              currentConfig.nostr.relays,
              undefined,
              genesisEntryId,
              admin.ndk
            )
            await publishInvitedEventIfNeeded(inviterPubkey, existingKey.pubkey, admin, req.id)
          }

          await grantPermissions(req, username, clientPubkey)
          log.admin('permissions re-granted for existing user')

          return admin.rpc.sendResponse(req.id, req.pubkey, existingKey.pubkey, KIND_ADMIN_RESPONSE)
        }
      }
      throw e
    }

    const identityKeypair = keygen('ml-dsa-44')
    const encKeypair = keygen('secp256k1-nip44')

    const identitySecretHex = bytesToHex(identityKeypair.secretKey)
    const identityPubkeyHex = bytesToHex(identityKeypair.publicKey)
    const encSecretHex = bytesToHex(encKeypair.secretKey)
    const encPubkeyHex = bytesToHex(encKeypair.publicKey)

    const keyName = username
    const encKeyName = `${username}#enc`

    log.admin(`Created dual keypair for ${username}`)

    log.admin(`Encrypting keys for ${keyName}`)
    const encryptedIdentityData = encryptPrivateKey(identitySecretHex, keyName)
    const encryptedEncData = encryptPrivateKey(encSecretHex, encKeyName)

    log.admin(`Backing up keys for ${keyName}`)
    const backupResult1 = await backupKey(keyName, encryptedIdentityData, identityPubkeyHex)
    if (!backupResult1.success) {
      throw new Error(`Backup failed for ${keyName}: ${backupResult1.error}`)
    }
    const backupResult2 = await backupKey(encKeyName, encryptedEncData, encPubkeyHex)
    if (!backupResult2.success) {
      throw new Error(`Backup failed for ${encKeyName}: ${backupResult2.error}`)
    }

    log.admin(`Storing keys locally for ${keyName}`)
    await storeKey(keyName, identitySecretHex, identityPubkeyHex, 'ml-dsa-44', 'identity')
    await markKeyBackedUp(keyName)

    await storeKey(encKeyName, encSecretHex, encPubkeyHex, 'secp256k1-nip44', 'enc', keyName)
    await markKeyBackedUp(encKeyName)

    if (admin.loadKey) {
      await admin.loadKey(keyName, identitySecretHex, 'ml-dsa-44')
    }

    const currentConfig = await admin.config()
    const daemonServiceEntryId = admin.getPlatformServiceEntryId?.()
    if (!daemonServiceEntryId) {
      throw new Error('Signer daemon has no verified platformServiceEntryId')
    }

    const identitySigner = new NDKMlDsaSigner(identitySecretHex)

    const { publishGenesisEntry } = await import('../../lib/keychain-event.js')
    const genesisEntryId = await publishGenesisEntry(
      identitySigner,
      identityPubkeyHex,
      currentConfig.nostr.relays,
      daemonServiceEntryId,
      undefined,
      admin.ndk,
      encPubkeyHex
    )
    log.admin(`[${req.id}] Kind 297 genesis published for ${username} (id: ${genesisEntryId})`)

    await publishUsernameEvent(
      identitySigner,
      username,
      identityPubkeyHex,
      currentConfig.nostr.relays,
      undefined,
      genesisEntryId,
      admin.ndk
    )
    log.admin(`[${req.id}] Kind 415 published for ${username} with kid ${genesisEntryId}`)

    await publishInvitedEventIfNeeded(inviterPubkey, identityPubkeyHex, admin, req.id)

    await grantPermissions(req, keyName, clientPubkey)

    checkpointService.broadcast('signer.command.completed', {
      method: 'create_account',
      keyName,
      pubkey: identityPubkeyHex.substring(0, 16)
    })

    scope.logResponse({
      userPubkey: identityPubkeyHex,
      userIdentifier: keyName,
      responseEventId: undefined,
      clientPubkey: clientPubkey || req.pubkey
    })

    checkpointService.broadcast('signer.response.sent', {
      method: 'create_account',
      kind: KIND_ADMIN_RESPONSE
    })

    return admin.rpc.sendResponse(req.id, req.pubkey, identityPubkeyHex, KIND_ADMIN_RESPONSE)
  } catch (e: any) {
    log.admin(`error creating account: ${e.message}`)
    scope.logError(e, { username })
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', KIND_ADMIN_RESPONSE, e.message)
  }
}

async function publishInvitedEventIfNeeded(
  inviterPubkey: string | undefined,
  inviteePubkey: string,
  admin: AdminInterface,
  correlationId?: string
): Promise<void> {
  if (!inviterPubkey) return

  const prefix = correlationId ? `[${correlationId}]` : ''
  log.admin(`${prefix} Resolving inviter private key for pubkey ${inviterPubkey}`)

  let inviterKeyRecord = await prisma.key.findFirst({
    where: { pubkey: inviterPubkey, role: 'identity', status: 'ACTIVE' }
  })
  if (!inviterKeyRecord) {
    const activeKeys = await prisma.key.findMany({
      where: { role: 'identity', status: 'ACTIVE' }
    })
    inviterKeyRecord = activeKeys.find((k) => identityIdFromPublicKey(k.pubkey) === inviterPubkey) ?? null
  }
  if (!inviterKeyRecord) {
    throw new Error(`Inviter public key or UID not found or not active: ${inviterPubkey}`)
  }
  const inviterPrivateKeyHex = await retrieveKey(inviterKeyRecord.keyName)
  if (!inviterPrivateKeyHex) {
    throw new Error(`Failed to decrypt inviter private key for ${inviterKeyRecord.keyName}`)
  }
  const isMlDsaInviter = inviterKeyRecord.algorithm === 'ml-dsa-44' || inviterPrivateKeyHex.length === 5120
  const inviterSigner = isMlDsaInviter
    ? new NDKMlDsaSigner(inviterPrivateKeyHex)
    : new NDKPrivateKeySigner(inviterPrivateKeyHex)
  const currentConfig = await admin.config()
  const { publishInvitedEvent } = await import('../../lib/invited-event.js')
  const inviterUid = identityIdFromPublicKey(inviterKeyRecord.pubkey)
  const inviterEntry = await queryCurrentIdentityEntry(admin.ndk, inviterUid)
  await publishInvitedEvent(inviterSigner, inviteePubkey, currentConfig.nostr.relays, undefined, inviterEntry?.id, admin.ndk)
  log.admin(`${prefix} Kind 723 published for invitee ${inviteePubkey.substring(0, 16)}... by inviter ${inviterKeyRecord.keyName}`)
}

async function grantPermissions(req: NDKRpcRequest, keyName: string, clientPubkey?: string) {
  await allowAllRequestsFromKey(req.pubkey, keyName, 'connect', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'sign_event', undefined, 'registrar', { kind: null })
  await allowAllRequestsFromKey(req.pubkey, keyName, 'nip44_encrypt', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'nip44_decrypt', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'switch_relays', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'get_public_key', undefined, 'registrar')
  await allowAllRequestsFromKey(req.pubkey, keyName, 'ping', undefined, 'registrar')

  if (clientPubkey) {
    await allowAllRequestsFromKey(clientPubkey, keyName, 'connect', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'sign_event', undefined, 'client', { kind: null })
    await allowAllRequestsFromKey(clientPubkey, keyName, 'nip44_encrypt', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'nip44_decrypt', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'switch_relays', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'get_public_key', undefined, 'client')
    await allowAllRequestsFromKey(clientPubkey, keyName, 'ping', undefined, 'client')
  }
}
