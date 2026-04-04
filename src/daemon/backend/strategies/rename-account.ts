import { IEventHandlingStrategy, NDKNip46Backend } from '@nostr-dev-kit/ndk'
import renameAccount from '../../admin/commands/rename_account.js'
import { log, logError } from '../../../lib/logger.js'
import { IConfig } from '../../../config/index.js'

export class RenameAccountHandlingStrategy implements IEventHandlingStrategy {
  private config: IConfig

  constructor(config: IConfig) {
    this.config = config
  }

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    log.daemon(`Signer: Handling rename_account NIP-46 request from ${remotePubkey}`)
    
    try {
      // The renameAccount command expects: currentConfig, params, remotePubkey, eventId
      // params usually matches [pubkey, newUsername, correlationId]
      const result = await renameAccount(this.config, params, remotePubkey, id)
      return result
    } catch (e: any) {
      logError('daemon', `Signer: rename_account failed: ${e.message}`, e)
      // Propagate error to RPC loop which will send it back to the client
      throw e
    }
  }
}
