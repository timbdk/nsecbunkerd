import { NDKKind, NDKRpcRequest } from '@nostr-dev-kit/ndk'
import AdminInterface from '../index.js'
import { allowAllRequestsFromKey } from '../../lib/acl/index.js'
import prisma from '../../../db.js'
import createDebug from 'debug'
import { checkpointService } from '../../../services/CheckpointService.js'

const debug = createDebug('nsecbunker:authorizeUser')

/**
 * Authorizes a user to sign events with an existing key.
 * Called during login flow (key already exists from registration).
 *
 * This grants the same permissions as create_account, but for an existing key.
 * Used when a user logs in and needs to establish their signing session.
 *
 * Params: [keyName, userPubkey]
 * - keyName: The NIP-05 style key name (e.g., "username@verity.local")
 * - userPubkey: The hex pubkey of the user's key
 */
export default async function authorizeUser(admin: AdminInterface, req: NDKRpcRequest) {
  const [keyName, userPubkey] = req.params as [string, string]

  if (!keyName || !userPubkey) {
    debug(`Invalid params: keyName=${keyName}, userPubkey=${userPubkey}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, 'Invalid params: keyName and userPubkey required')
  }

  debug(`Authorizing user ${userPubkey.slice(0, 16)}... for key ${keyName}`)

  // Verify the key exists
  const key = await prisma.key.findUnique({ where: { keyName } })
  if (!key) {
    debug(`Key not found: ${keyName}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, `Key not found: ${keyName}`)
  }

  // Verify the pubkey matches
  if (key.pubkey !== userPubkey) {
    debug(`Pubkey mismatch: expected ${key.pubkey.slice(0, 16)}..., got ${userPubkey.slice(0, 16)}...`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, 'Pubkey mismatch')
  }

  try {
    // Grant all standard permissions (same as create_account)
    await allowAllRequestsFromKey(userPubkey, keyName, 'connect')
    await allowAllRequestsFromKey(userPubkey, keyName, 'sign_event', undefined, undefined, {
      kind: 'all'
    })
    await allowAllRequestsFromKey(userPubkey, keyName, 'encrypt')
    await allowAllRequestsFromKey(userPubkey, keyName, 'decrypt')
    // NDK calls these utility methods during blockUntilReady() after the initial 'connect' handshake.
    // The requests are sent from the client's ephemeral keypair, so authorize_client.ts is the primary
    // gate. We grant defensively here too: the ACL resolves by (keyName, remotePubkey) and we can't be
    // certain the NIP-46 backend won't look up the user pubkey for these methods.
    await allowAllRequestsFromKey(userPubkey, keyName, 'switch_relays')
    await allowAllRequestsFromKey(userPubkey, keyName, 'get_public_key')
    await allowAllRequestsFromKey(userPubkey, keyName, 'ping')

    debug(`User ${userPubkey.slice(0, 16)}... authorized for key ${keyName}`)

    checkpointService.broadcast('signer.command.completed', {
      method: 'authorize_client',
      keyName,
    })

    checkpointService.broadcast('signer.response.sent', {
      method: 'authorize_client',
    })

    return admin.rpc.sendResponse(req.id, req.pubkey, 'authorized', NDKKind.NostrConnect)
  } catch (e: any) {
    debug(`Error authorizing user: ${e.message}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, e.message)
  }
}
