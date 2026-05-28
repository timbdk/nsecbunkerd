import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import { KIND_ADMIN_RESPONSE, type RevokeUserInput } from 'verity-event-data-module'
import AdminInterface, { type ValidatedRpcRequest } from '../index.js'
import prisma from '../../../db.js'
import { log } from '../../../lib/logger.js'
import { checkpointService } from '../../../services/CheckpointService.js'


/**
 * Revokes all clients' permission to sign events for a specific user key.
 * Used when all devices should be logged out simultaneously (e.g., security event).
 *
 * Params: [keyName, userPubkey, correlationId?]
 */
export default async function revokeUser(admin: AdminInterface, req: ValidatedRpcRequest<RevokeUserInput>) {
  const { keyName, userPubkey, correlationId } = req.validatedParams

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
      kind: KIND_ADMIN_RESPONSE,
    })

    // Include user-only attestation tag so the relay clears ALL device mappings for this user
    const attestationTags = [['user', userPubkey]]
    return admin.rpc.sendResponse(req.id, req.pubkey, 'revoked', KIND_ADMIN_RESPONSE, undefined, attestationTags)
  } catch (e: any) {
    log.admin(`Error revoking user: ${e.message}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', KIND_ADMIN_RESPONSE, e.message)
  }
}
