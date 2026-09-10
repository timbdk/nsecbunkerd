/**
 * KeyService - Encrypted key storage and retrieval
 *
 * Uses AES-256-GCM for authenticated encryption of private keys.
 * Master key is derived from SIGNER_KEK env var (memory-only).
 */

import crypto from 'crypto'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { publicKeyFromSecret } from 'verity-event-data-module'
import prisma from '../db.js'
import { logError } from '../lib/logger.js'

const ALGORITHM = 'aes-256-gcm'

/**
 * Get KEK from environment.
 * Throws if not set - this is intentional, we want to fail fast.
 */
function getMasterKey(): Buffer {
  const kekHex = process.env.SIGNER_KEK
  if (!kekHex) {
    throw new Error('CRITICAL: SIGNER_KEK environment variable not set. This key must be in memory only and never touch disk.')
  }
  if (kekHex.length !== 64) {
    throw new Error('CRITICAL: SIGNER_KEK must be a 64-character hex string (256 bits)')
  }
  return Buffer.from(kekHex, 'hex')
}

/**
 * Derive a per-key encryption key using HKDF.
 * This ensures each key has unique encryption even with same master key.
 */
function deriveKeyEncryptionKey(masterKey: Buffer, keyName: string): Buffer {
  const salt = Buffer.from(keyName, 'utf8')
  const info = Buffer.from('verity-key-encryption', 'utf8')
  return crypto.hkdfSync('sha256', masterKey, salt, info, 32)
}

/**
 * Encrypt a private key using AES-256-GCM.
 */
export function encryptPrivateKey(privateKeyHex: string, keyName: string): { encryptedKey: string; iv: string; authTag: string } {
  const masterKey = getMasterKey()
  const kek = deriveKeyEncryptionKey(masterKey, keyName)

  const iv = crypto.randomBytes(12) // 96 bits for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv)

  const plaintext = Buffer.from(privateKeyHex, 'hex')
  let ciphertext = cipher.update(plaintext)
  ciphertext = Buffer.concat([ciphertext, cipher.final()])

  return {
    encryptedKey: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex')
  }
}

/**
 * Decrypt a private key using AES-256-GCM.
 */
export function decryptPrivateKey(encryptedKey: string, iv: string, authTag: string, keyName: string): string {
  const masterKey = getMasterKey()
  const kek = deriveKeyEncryptionKey(masterKey, keyName)

  const decipher = crypto.createDecipheriv(ALGORITHM, kek, Buffer.from(iv, 'hex'))
  decipher.setAuthTag(Buffer.from(authTag, 'hex'))

  let plaintext = decipher.update(Buffer.from(encryptedKey, 'hex'))
  plaintext = Buffer.concat([plaintext, decipher.final()])

  return plaintext.toString('hex')
}

/**
 * Store an encrypted key in the database.
 */
export async function storeKey(
  keyName: string,
  privateKeyHex: string,
  pubkey: string,
  algorithm: string,
  role: string,
  parentKeyName?: string | null
): Promise<void> {
  const { encryptedKey, iv, authTag } = encryptPrivateKey(privateKeyHex, keyName)

  await prisma.key.upsert({
    where: { keyName },
    create: {
      keyName,
      pubkey,
      algorithm,
      role,
      parentKeyName: parentKeyName ?? null,
      encryptedKey,
      iv,
      authTag
    },
    update: {
      pubkey,
      algorithm,
      role,
      parentKeyName: parentKeyName ?? null,
      encryptedKey,
      iv,
      authTag,
      updatedAt: new Date()
    }
  })
}

/**
 * Mark a key as backed up.
 */
export async function markKeyBackedUp(keyName: string): Promise<void> {
  await prisma.key.update({
    where: { keyName },
    data: { backedUpAt: new Date() }
  })
}

/**
 * Retrieve and decrypt a key from the database.
 * Returns the decrypted private key hex, or null if not found.
 */
export async function retrieveKey(keyName: string): Promise<string | null> {
  const key = await prisma.key.findUnique({
    where: { keyName }
  })

  if (!key || !key.encryptedKey || !key.iv || !key.authTag) {
    return null
  }

  return decryptPrivateKey(key.encryptedKey, key.iv, key.authTag, keyName)
}

export interface KeyFamily {
  identity: { keyName: string; pubkey: string; privateKeyHex: string; algorithm: string }
  enc?: { keyName: string; pubkey: string; privateKeyHex: string; algorithm: string }
}

/**
 * Resolve an identity's key family using column-based grouping.
 */
export async function resolveKeyFamily(identityKeyName: string): Promise<KeyFamily | null> {
  const identityRow = await prisma.key.findUnique({
    where: { keyName: identityKeyName }
  })
  if (!identityRow || identityRow.status !== 'ACTIVE' || identityRow.role !== 'identity') {
    return null
  }

  const identityPrivateKeyHex = await retrieveKey(identityKeyName)
  if (!identityPrivateKeyHex) return null

  const encRow = await prisma.key.findFirst({
    where: { parentKeyName: identityKeyName, role: 'enc', status: 'ACTIVE' }
  })

  let enc: KeyFamily['enc'] | undefined
  if (encRow) {
    const encPrivateKeyHex = await retrieveKey(encRow.keyName)
    if (encPrivateKeyHex) {
      enc = {
        keyName: encRow.keyName,
        pubkey: encRow.pubkey,
        privateKeyHex: encPrivateKeyHex,
        algorithm: encRow.algorithm
      }
    }
  }

  return {
    identity: {
      keyName: identityRow.keyName,
      pubkey: identityRow.pubkey,
      privateKeyHex: identityPrivateKeyHex,
      algorithm: identityRow.algorithm
    },
    enc
  }
}

/**
 * Validate all keys in the database can be decrypted correctly.
 * Returns list of failed key names.
 */
export async function validateAllKeys(): Promise<{
  total: number
  valid: number
  failed: string[]
}> {
  const keys = await prisma.key.findMany({
    where: {
      status: 'ACTIVE'
    }
  })

  const failed: string[] = []

  for (const key of keys) {
    if (!key.encryptedKey || !key.iv || !key.authTag) {
      failed.push(key.keyName)
      continue
    }

    try {
      const decryptedHex = decryptPrivateKey(key.encryptedKey, key.iv, key.authTag, key.keyName)

      // Verify the decrypted key produces the correct pubkey based on algorithm
      const derivedPubkeyBytes = publicKeyFromSecret(key.algorithm, decryptedHex)
      const derivedPubkey = bytesToHex(derivedPubkeyBytes)

      if (derivedPubkey !== key.pubkey) {
        logError('keys', `Key ${key.keyName}: pubkey mismatch. ` + `Expected ${key.pubkey}, got ${derivedPubkey}`)
        failed.push(key.keyName)
      }
    } catch (e: any) {
      logError('keys', `Key ${key.keyName}: decryption failed - ${e.message}`, e)
      failed.push(key.keyName)
    }
  }

  return {
    total: keys.length,
    valid: keys.length - failed.length,
    failed
  }
}

