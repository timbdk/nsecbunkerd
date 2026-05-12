import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import { KIND_ADMIN_RESPONSE } from 'verity-event-validation-module'
import AdminInterface from '../index.js'

export default async function ping(admin: AdminInterface, req: NDKRpcRequest) {
  return admin.rpc.sendResponse(req.id, req.pubkey, 'ok', KIND_ADMIN_RESPONSE)
}
