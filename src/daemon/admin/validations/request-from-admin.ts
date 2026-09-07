import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import { identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../../lib/logger.js'

export async function validateRequestFromAdmin(req: NDKRpcRequest, allowedUids: string[]): Promise<boolean> {
  const hexpubkey = req.pubkey

  if (!hexpubkey) {
    log.admin('missing pubkey')
    return false
  }

  const callerUid = identityIdFromPublicKey(hexpubkey)
  return allowedUids.includes(hexpubkey) || allowedUids.includes(callerUid)
}
