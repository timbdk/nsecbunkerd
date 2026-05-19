import { KIND_ADMIN_RESPONSE } from 'verity-event-validation-module'
import AdminInterface, { type ValidatedRpcRequest } from '../index.js'

export default async function ping(admin: AdminInterface, req: ValidatedRpcRequest<any>) {
  return admin.rpc.sendResponse(req.id, req.pubkey, 'ok', KIND_ADMIN_RESPONSE)
}
