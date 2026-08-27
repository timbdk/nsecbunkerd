import { NDKRpcRequest } from '@nostr-dev-kit/ndk'
import { nip19 } from 'nostr-tools'
import { identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../../lib/logger.js'

export async function validateRequestFromAdmin(req: NDKRpcRequest, npubs: string[]): Promise<boolean> {
  const hexpubkey = req.pubkey

  if (!hexpubkey) {
    log.admin('missing pubkey')
    return false
  }

  const hexpubkeys: string[] = []
  const uids: string[] = []

  for (const item of npubs) {
    if (!item) continue
    if (/^[0-9a-fA-F]{64}$/.test(item)) {
      hexpubkeys.push(item)
      uids.push(item)
    } else if (item.startsWith('npub1')) {
      try {
        const decoded = nip19.decode(item).data as string
        hexpubkeys.push(decoded)
        uids.push(identityIdFromPublicKey(decoded))
      } catch {}
    }
  }

  return hexpubkeys.includes(hexpubkey) || uids.includes(hexpubkey)
}
