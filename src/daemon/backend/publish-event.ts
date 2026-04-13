import { NDKNip46Backend } from '@nostr-dev-kit/ndk'
import { IEventHandlingStrategy } from '@nostr-dev-kit/ndk'
import { log } from '../../lib/logger.js'

export default class PublishEventHandlingStrategy implements IEventHandlingStrategy {
  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    const event = await backend.signEvent(remotePubkey, params)
    if (!event) return undefined

    log.backend('Publishing event', event)
    await event.publish()

    return JSON.stringify(await event.toNostrEvent())
  }
}
