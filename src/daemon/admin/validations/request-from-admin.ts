import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import { nip19 } from 'nostr-tools'
import { log } from '../../../lib/logger.js'

export async function validateRequestFromAdmin(req: NDKRpcRequest, npubs: string[]): Promise<boolean> {
  const hexpubkey = req.pubkey

  if (!hexpubkey) {
    log.admin('missing pubkey')
    return false
  }

  const hexpubkeys = npubs.map((npub) => nip19.decode(npub).data as string)

  return hexpubkeys.includes(hexpubkey)
}
