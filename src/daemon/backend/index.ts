import NDK, { NDKNip46Backend, NDKPrivateKeySigner, Nip46PermitCallback } from '@nostr-dev-kit/ndk'
import { IConfig } from '../../config/index.js'

export class Backend extends NDKNip46Backend {
  constructor(ndk: NDK, key: string, cb: Nip46PermitCallback, config: IConfig) {
    const signer = new NDKPrivateKeySigner(key)
    // Pass an empty relay list so NDKNip46Backend skips creating a separate
    // RPC pool and shares the daemon's main NDK pool instead. The main pool
    // is already connected and NIP-42 authenticated with the relay.
    // This avoids duplicate WebSocket connections and prevents internal Docker
    // relay URLs (ws://relay:7777) from being advertised to clients.
    super(ndk, signer, cb, [])
  }
}
