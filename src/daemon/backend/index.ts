import NDK, {
  NDKNip46Backend,
  NDKMlDsaSigner,
  NDKPrivateKeySigner,
  NDKTransportCredential,
  NDKEvent,
  NDKUser,
  Nip46PermitCallback,
  IEventHandlingStrategy
} from '@nostr-dev-kit/ndk'
import { IConfig } from '../../config/index.js'
import type { KeyFamily } from '../../services/KeyService.js'
import { queryCurrentIdentityEntry } from '../lib/keychain-event.js'
import { identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../lib/logger.js'

export async function validateKidNomination(
  ndk: NDK,
  candidateKid: string | undefined,
  identityUid: string
): Promise<void> {
  if (!candidateKid) {
    throw new Error(`[KID_NOMINATION_INVALID] missing: kid tag is required`)
  }

  const current = await queryCurrentIdentityEntry(ndk, identityUid)
  if (!current || current.id !== candidateKid) {
    throw new Error(`[KID_NOMINATION_INVALID] ${candidateKid}: not the current active identity key entry`)
  }

  // Defensive check: queryCurrentIdentityEntry resolves via currentIdentityEntry
  // which filters to genesis/rotate, but we verify here as defense-in-depth.
  if (current.variant !== 'genesis' && current.variant !== 'rotate') {
    throw new Error(`[KID_NOMINATION_INVALID] ${candidateKid}: entry is variant '${current.variant}', not an identity key entry`)
  }
}

export class VeritySignEventStrategy implements IEventHandlingStrategy {
  constructor(private backend: Backend, private family: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    const [eventString] = params
    const parsedEvent = JSON.parse(eventString)
    const event = new NDKEvent(backend.ndk, parsedEvent)

    if (parsedEvent.uid) event.uid = parsedEvent.uid
    if (parsedEvent.kid) (event as any).kid = parsedEvent.kid
    if (parsedEvent.id) event.id = parsedEvent.id

    // Check ACL authorization before performing any relay queries
    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'sign_event',
        params: event
      }))
    ) {
      log.signing(`sign_event request from ${remotePubkey} rejected by ACL`)
      return undefined
    }

    // Nomination validation (relay round-trip, only after client is authorized)
    const identityUid = identityIdFromPublicKey(this.family.identity.pubkey)
    await validateKidNomination(backend.ndk, (event as any).kid, identityUid)

    // Sign with ML-DSA identity signer
    await event.sign(this.backend.identitySigner)

    // Preserve verbatim template fields on raw event
    const raw = event.rawEvent()
    if (parsedEvent.uid) (raw as any).uid = parsedEvent.uid
    if (parsedEvent.kid) (raw as any).kid = parsedEvent.kid

    return JSON.stringify(raw)
  }
}

export class VerityNip44EncryptStrategy implements IEventHandlingStrategy {
  constructor(private backend: Backend, private family: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    if (!this.backend.encSigner) {
      throw new Error('No encryption key configured for account')
    }

    const [recipientPubkey, payload] = params
    const ownIdentityPubkey = this.family.identity.pubkey
    const ownUid = identityIdFromPublicKey(ownIdentityPubkey)
    const ownEncPubkey = this.family.enc?.pubkey

    let targetPubkey = recipientPubkey
    if (targetPubkey === ownIdentityPubkey || targetPubkey === ownUid || targetPubkey === ownEncPubkey) {
      targetPubkey = (await this.backend.encSigner.user()).pubkey
    }

    const recipientUser = new NDKUser({ pubkey: targetPubkey })

    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'nip44_encrypt',
        params: payload
      }))
    ) {
      return undefined
    }

    return await this.backend.encSigner.encrypt(recipientUser, payload, 'nip44')
  }
}

export class VerityNip44DecryptStrategy implements IEventHandlingStrategy {
  constructor(private backend: Backend, private family: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    if (!this.backend.encSigner) {
      throw new Error('No encryption key configured for account')
    }

    const [senderPubkey, payload] = params
    const ownIdentityPubkey = this.family.identity.pubkey
    const ownUid = identityIdFromPublicKey(ownIdentityPubkey)
    const ownEncPubkey = this.family.enc?.pubkey

    let targetPubkey = senderPubkey
    if (targetPubkey === ownIdentityPubkey || targetPubkey === ownUid || targetPubkey === ownEncPubkey) {
      targetPubkey = (await this.backend.encSigner.user()).pubkey
    }

    const senderUser = new NDKUser({ pubkey: targetPubkey })

    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'nip44_decrypt',
        params: payload
      }))
    ) {
      return undefined
    }

    return await this.backend.encSigner.decrypt(senderUser, payload, 'nip44')
  }
}

export class Backend extends NDKNip46Backend {
  public identitySigner: NDKMlDsaSigner | NDKPrivateKeySigner
  public encSigner?: NDKPrivateKeySigner

  constructor(ndk: NDK, family: KeyFamily, cb: Nip46PermitCallback, config: IConfig) {
    const isMlDsa = family.identity.algorithm === 'ml-dsa-44'
    const identitySigner = isMlDsa
      ? new NDKMlDsaSigner(family.identity.privateKeyHex)
      : new NDKPrivateKeySigner(family.identity.privateKeyHex)

    const encSigner = family.enc
      ? new NDKPrivateKeySigner(family.enc.privateKeyHex)
      : (!isMlDsa ? (identitySigner as NDKPrivateKeySigner) : undefined)

    const credential = isMlDsa && encSigner
      ? new NDKTransportCredential(identitySigner as NDKMlDsaSigner, encSigner, ndk)
      : identitySigner

    super(ndk, credential, cb, [])
    this.identitySigner = identitySigner
    this.encSigner = encSigner

    this.setStrategy('sign_event', new VeritySignEventStrategy(this, family))
    this.setStrategy('nip44_encrypt', new VerityNip44EncryptStrategy(this, family))
    this.setStrategy('nip44_decrypt', new VerityNip44DecryptStrategy(this, family))
  }
}
