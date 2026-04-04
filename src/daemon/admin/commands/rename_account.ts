import { NDKPrivateKeySigner } from '@nostr-dev-kit/ndk'
import { IConfig, getCurrentConfig } from '../../../config'
import { publishUsernameEvent } from '../../lib/username-event'
import prisma from '../../../db'
import { log, logError } from '../../../lib/logger'
import { retrieveKey } from '../../../services/KeyService'

export async function validate(currentConfig: IConfig, pubkey: string, newUsername: string) {
  if (!pubkey) {
    throw new Error('pubkey is required')
  }
  if (!newUsername) {
    throw new Error('newUsername is required')
  }

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
  currentConfig: IConfig,
  params: string[],
  remotePubkey: string,
  eventId: string
): Promise<string> {
  // Expected params: [pubkey, newUsername, correlationId?]
  const pubkey = params[0]
  const newUsername = params[1]
  const correlationId = params[2] || 'none'

  const { relayUrls } = await validate(currentConfig, pubkey, newUsername)

  log.admin(`rename_account request received: pubkey=${pubkey}, username=${newUsername}`)

  // Retrieve existing key from DB by pubkey
  const keyRecord = await prisma.key.findFirst({
    where: { pubkey }
  })

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
  if (userObj.pubkey !== pubkey) {
      logError('admin', `rename_account failed: decrypted key pubkey mismatch for ${pubkey}`)
      throw new Error(`Internal error: key pubkey mismatch`)
  }

  log.admin(`Found account: ${keyRecord.keyName}. Emitting new Kind 415...`)

  // Publish the new Kind 415 event
  await publishUsernameEvent(userSigner, newUsername, pubkey, relayUrls)

  log.admin(`rename_account completed for pubkey=${pubkey}, username=${newUsername}`)

  return `Account renamed to ${newUsername}`
}
