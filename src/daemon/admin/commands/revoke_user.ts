import { NDKKind, NDKRpcRequest } from '@nostr-dev-kit/ndk'
import AdminInterface from '../index.js'
import { rejectAllRequestsFromKey } from '../../lib/acl/index.js'
import prisma from '../../../db.js'
import { log } from '../../../lib/logger.js'
import { checkpointService } from '../../../services/CheckpointService.js'


/**
 * Revokes all clients' permission to sign events for a specific user key.
 * Used when all devices should be logged out simultaneously (e.g., security event).
 *
 * Param format: [keyName, userPubkey]
 */
export default async function revokeUser(admin: AdminInterface, req: NDKRpcRequest) {
  const params = req.params as string[]

  if (params.length === 2 && params[0].includes('@')) {
    return revokeAllClients(admin, req, params[0], params[1])
  } else {
    log.admin(`Invalid params: ${JSON.stringify(params)}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, 'Invalid params')
  }
}

async function revokeAllClients(admin: AdminInterface, req: NDKRpcRequest, keyName: string, userPubkey: string) {
  log.admin(`Revoking ALL clients from key ${keyName}`)

  try {

    // In Verity, `revoke_user` revokes all sessions active for a key.
    await prisma.session.updateMany({
      where: { keyName, revokedAt: null },
      data: { revokedAt: new Date() }
    })
    
    log.admin(`All clients revoked for key ${keyName}`)

    checkpointService.broadcast('signer.command.completed', {
      method: 'revoke_user',
      keyName,
    })

    checkpointService.broadcast('signer.response.sent', {
      method: 'revoke_user',
    })

    return admin.rpc.sendResponse(req.id, req.pubkey, 'revoked', NDKKind.NostrConnect)
  } catch (e: any) {
    log.admin(`Error revoking user: ${e.message}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, e.message)
  }
}
