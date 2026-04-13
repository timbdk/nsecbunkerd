import { NDKKind, NDKRpcRequest } from '@nostr-dev-kit/ndk'
import AdminInterface from '../index.js'
import { rejectAllRequestsFromKey } from '../../lib/acl/index.js'
import prisma from '../../../db.js'
import { log } from '../../../lib/logger.js'
import { checkpointService } from '../../../services/CheckpointService.js'


/**
 * Revokes a client's permission to sign events with a user's key.
 * Called during logout flow to invalidate the client's signing session.
 *
 * Params: [keyName, userPubkey, clientPubkey?, correlationId?]
 * - keyName: The NIP-05 style key name (e.g., "username@verity.local")
 * - userPubkey: The hex pubkey of the user (for verification)
 * - clientPubkey: The hex pubkey of the client to revoke (optional - if undefined, revokes all clients)
 * - correlationId: Optional correlation ID for tracing across services
 */
export default async function revokeClient(admin: AdminInterface, req: NDKRpcRequest) {
  const [keyName, userPubkey, clientPubkey, correlationId] = req.params as [string, string, string | undefined, string?]
  const corrPrefix = `[${correlationId?.slice(0, 8) || 'no-corr'}]`

  if (!keyName) {
    log.admin(`${corrPrefix} Invalid params: keyName required`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, 'Invalid params: keyName required')
  }

  log.admin(`${corrPrefix} Revoking ${clientPubkey ? 'client ' + clientPubkey.slice(0, 16) + '...' : 'ALL clients'} from key ${keyName}`)

  // Verify the key exists
  const key = await prisma.key.findUnique({ where: { keyName } })
  if (!key) {
    log.admin(`Key not found: ${keyName}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, `Key not found: ${keyName}`)
  }

  try {
    if (clientPubkey) {
      // Revoke specific client
      await rejectAllRequestsFromKey(clientPubkey, keyName)
      
      // Also mark session explicitly revoked
      await prisma.session.updateMany({
        where: { keyName, clientPubkey, revokedAt: null },
        data: { revokedAt: new Date() }
      })

      log.admin(`Client ${clientPubkey.slice(0, 16)}... revoked from key ${keyName}`)
    } else {
      // Revoke all clients 
      await prisma.session.updateMany({
        where: { keyName, revokedAt: null },
        data: { revokedAt: new Date() }
      })
      log.admin(`All clients revoked for user ${userPubkey?.slice(0, 16)}... on key ${keyName}`)
    }

    checkpointService.broadcast('signer.command.completed', {
      method: 'revoke_client',
      keyName,
      pubkey: userPubkey?.substring(0, 16),
    })

    checkpointService.broadcast('signer.response.sent', {
      method: 'revoke_client',
    })

    return admin.rpc.sendResponse(req.id, req.pubkey, 'revoked', NDKKind.NostrConnect)
  } catch (e: any) {
    log.admin(`Error revoking client: ${e.message}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, e.message)
  }
}
