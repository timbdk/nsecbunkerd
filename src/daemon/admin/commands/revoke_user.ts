import { NDKKind, NDKRpcRequest } from '@nostr-dev-kit/ndk'
import AdminInterface from '../index.js'
import { rejectAllRequestsFromKey } from '../../lib/acl/index.js'
import prisma from '../../../db.js'
import createDebug from 'debug'

const debug = createDebug('nsecbunker:revokeUser')

/**
 * Revokes a user's permission to sign events with a key.
 * Called during logout flow to invalidate the signing session.
 *
 * Supports two param formats:
 * 1. [keyUserId] - Legacy format, revokes by KeyUser database ID
 * 2. [keyName, userPubkey] - New format, revokes by key name and pubkey
 */
export default async function revokeUser(admin: AdminInterface, req: NDKRpcRequest) {
  const params = req.params as string[]

  // Detect param format
  if (params.length === 2 && params[0].includes('@')) {
    // New format: [keyName, userPubkey]
    return revokeByKeyNameAndPubkey(admin, req, params[0], params[1])
  } else if (params.length === 1) {
    // Legacy format: [keyUserId]
    return revokeByKeyUserId(admin, req, params[0])
  } else {
    debug(`Invalid params: ${JSON.stringify(params)}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, 'Invalid params')
  }
}

/**
 * Revoke by keyName and userPubkey (new format for login/logout flow)
 */
async function revokeByKeyNameAndPubkey(admin: AdminInterface, req: NDKRpcRequest, keyName: string, userPubkey: string) {
  debug(`Revoking user ${userPubkey.slice(0, 16)}... from key ${keyName}`)

  try {
    await rejectAllRequestsFromKey(userPubkey, keyName)
    debug(`User ${userPubkey.slice(0, 16)}... revoked from key ${keyName}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'revoked', NDKKind.NostrConnect)
  } catch (e: any) {
    debug(`Error revoking user: ${e.message}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', NDKKind.NostrConnect, e.message)
  }
}

/**
 * Revoke by KeyUser database ID (legacy format for admin UI)
 */
async function revokeByKeyUserId(admin: AdminInterface, req: NDKRpcRequest, keyUserIdStr: string) {
  const keyUserIdInt = parseInt(keyUserIdStr)
  if (isNaN(keyUserIdInt)) {
    debug(`Invalid keyUserId: ${keyUserIdStr}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', 24134, 'Invalid keyUserId')
  }

  debug(`Revoking keyUser by ID: ${keyUserIdInt}`)

  try {
    await prisma.keyUser.update({
      where: { id: keyUserIdInt },
      data: { revokedAt: new Date() }
    })

    const result = JSON.stringify(['ok'])
    return admin.rpc.sendResponse(req.id, req.pubkey, result, 24134)
  } catch (e: any) {
    debug(`Error revoking keyUser: ${e.message}`)
    return admin.rpc.sendResponse(req.id, req.pubkey, 'error', 24134, e.message)
  }
}
