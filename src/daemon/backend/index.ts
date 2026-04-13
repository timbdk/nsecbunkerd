import NDK, { NDKNip46Backend, NDKPrivateKeySigner, Nip46PermitCallback } from '@nostr-dev-kit/ndk'
import { IConfig } from '../../config/index.js'

export class Backend extends NDKNip46Backend {
  constructor(ndk: NDK, key: string, cb: Nip46PermitCallback, config: IConfig) {
    const signer = new NDKPrivateKeySigner(key)
    super(ndk, signer, cb)
  }
}
