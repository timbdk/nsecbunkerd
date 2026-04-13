/**
 * BackupService - Remote backup interface for encrypted keys
 *
 * In production, this will validate that keys are stored externally
 * before allowing local storage. For now, mock returns true.
 */

import { log } from '../lib/logger.js'


export interface BackupResult {
  success: boolean
  error?: string
  hash?: string
}

/**
 * Backup an encrypted key to remote storage.
 *
 * This is called BEFORE local storage - if backup fails,
 * registration should be aborted.
 *
 * Currently a mock that always succeeds. In production:
 * - Store to redundant remote storage
 * - Verify hash matches
 * - Return success only when confirmed
 */
export async function backupKey(
  keyName: string,
  encryptedData: {
    encryptedKey: string
    iv: string
    authTag: string
  },
  pubkey: string
): Promise<BackupResult> {
  log.keys(`Backing up key: ${keyName}`)

  // TODO: Implement real backup logic
  // - Store to remote service
  // - Verify hash
  // - Handle retries

  // Mock: always succeed
  log.keys(`Backup mock: key ${keyName} "backed up" successfully`)

  return {
    success: true,
    hash: hashData(JSON.stringify({ keyName, encryptedData, pubkey }))
  }
}

/**
 * Verify a key exists in remote backup.
 */
export async function verifyBackup(keyName: string): Promise<boolean> {
  log.keys(`Verifying backup for key: ${keyName}`)

  // Mock: always return true
  return true
}

/**
 * Restore a key from remote backup.
 */
export async function restoreFromBackup(keyName: string): Promise<{
  encryptedKey: string
  iv: string
  authTag: string
  pubkey: string
} | null> {
  log.keys(`Restoring key from backup: ${keyName}`)

  // Mock: return null (not implemented)
  return null
}

/**
 * Simple hash for verification.
 */
function hashData(data: string): string {
  const crypto = require('crypto')
  return crypto.createHash('sha256').update(data).digest('hex')
}
