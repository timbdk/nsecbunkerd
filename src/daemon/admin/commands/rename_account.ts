import { NDKPrivateKeySigner } from '@nostr-dev-kit/ndk'
import { KIND_ADMIN_RESPONSE, type RenameAccountInput } from 'verity-event-data-module'
import AdminInterface, { type ValidatedRpcRequest } from '../index.js'
import { IConfig } from '../../../config/index.js'
import { publishUsernameEvent } from '../../lib/username-event.js'
import prisma from '../../../db.js'
import { log, logError } from '../../../lib/logger.js'
import { retrieveKey } from '../../../services/KeyService.js'
import { checkpointService } from '../../../services/CheckpointService.js'

export async function validateRelays(currentConfig: IConfig) {

  // Determine relay URLs
  let relayUrls = currentConfig.nostr.relays
  if (!relayUrls || relayUrls.length === 0) {
    if (process.env.RELAY_URL) {
      relayUrls = [process.env.RELAY_URL]
    } else {
      throw new Error('No target relays configured for Kind 415 publication')
    }
  }

  return { relayUrls }
}

export default async function renameAccount(
  admin: AdminInterface,
  req: ValidatedRpcRequest<RenameAccountInput>
) {
  const currentConfig = await admin.config()
  const { userPubkey: pubkey, newUsername, correlationId } = req.validatedParams

  const { relayUrls } = await validateRelays(currentConfig)

  log.admin(`rename_account request received: pubkey=${pubkey}, username=${newUsername}`)

  const { identityIdFromPublicKey } = await import('verity-event-data-module')

  // Retrieve existing key from DB by pubkey, keyName, or derived identity UID
  let keyRecord = await prisma.key.findFirst({
    where: { pubkey }
  })
  if (!keyRecord) {
    keyRecord = await prisma.key.findFirst({
      where: { keyName: pubkey }
    })
  }
  if (!keyRecord) {
    const allKeys = await prisma.key.findMany()
    keyRecord = allKeys.find((k: any) => identityIdFromPublicKey(k.pubkey) === pubkey) || null
  }

  if (!keyRecord) {
    logError('admin', `rename_account failed: No key found for pubkey ${pubkey}`)
    throw new Error(`Account not found for pubkey ${pubkey}`)
  }

  // Retrieve and decrypt the user's private key
  const nsec = await retrieveKey(keyRecord.keyName)
  if (!nsec) {
    logError('admin', `rename_account failed: Could not retrieve key for ${keyRecord.keyName}`)
    throw new Error(`Internal error: key retrieval failed`)
  }

  const userSigner = new NDKPrivateKeySigner(nsec)
  
  // Actually verify that the derived pubkey is the same (sanity check)
  const userObj = await userSigner.user()
  const derivedUid = identityIdFromPublicKey(userObj.pubkey)
  if (userObj.pubkey !== pubkey && derivedUid !== pubkey && keyRecord.keyName !== pubkey) {
      logError('admin', `rename_account failed: decrypted key pubkey mismatch for ${pubkey}`)
      throw new Error(`Internal error: key pubkey mismatch`)
  }

  log.admin(`Found account: ${keyRecord.keyName}. Emitting new Kind 415...`)

  // Query own chain to find current identity entry id for kid
  const { queryCurrentIdentityEntry } = await import('../../lib/keychain-event.js')
  const currentIdentity = await queryCurrentIdentityEntry(admin.ndk, derivedUid)

  // Publish the new Kind 415 event with kid
  await publishUsernameEvent(userSigner, newUsername, userObj.pubkey, relayUrls, undefined, currentIdentity?.id, admin.ndk)

  log.admin(`rename_account completed for pubkey=${pubkey}, username=${newUsername}`)

  checkpointService.broadcast('signer.command.completed', {
    method: 'rename_account',
    id: req.id?.substring(0, 16),
  })

  checkpointService.broadcast('signer.response.sent', {
    method: 'rename_account',
    kind: KIND_ADMIN_RESPONSE,
  })

  return admin.rpc.sendResponse(req.id, req.pubkey, `Account renamed to ${newUsername}`, KIND_ADMIN_RESPONSE)
}
