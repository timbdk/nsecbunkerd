/**
 * Purpose: Validation module for signer daemon environment variables and configuration files.
 * Behavior: Validates required keys, lengths, hex formats, and rejects legacy configuration shapes.
 * Usage: Invoked during daemon startup and in testing harnesses to guarantee environment integrity.
 */

import { publicKeyFromSecret } from 'verity-event-data-module'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

// ── Legacy Configuration Guard ───────────────────────────────────────────────

/**
 * Checks if a parsed configuration object contains legacy nsecbunker.json key material.
 * Returns true if legacy admin.key, keys.admin, or non-empty admin.npubs are present.
 */
export function isLegacyConfigFile(raw: any): boolean {
  if (!raw || typeof raw !== 'object') return false

  const hasAdminKey = Boolean(raw.admin?.key || raw.keys?.admin)
  const hasAdminNpubs = Array.isArray(raw.admin?.npubs)
    ? raw.admin.npubs.length > 0
    : Boolean(raw.admin?.npubs && typeof raw.admin.npubs === 'string' && raw.admin.npubs.trim().length > 0)

  return hasAdminKey || hasAdminNpubs
}

// ── Environment Validation ───────────────────────────────────────────────────

export interface DaemonEnvValidationResult {
  valid: boolean
  error?: string
}

/**
 * Validates the daemon environment against Phase 03 SSOT requirements.
 * Enforces SIGNER_KEK, SIGNER_DAEMON_KEY, SIGNER_DAEMON_ECDH_KEY, and VERITY_PLATFORM_ID.
 */
export function validateDaemonEnvironment(env: NodeJS.ProcessEnv): DaemonEnvValidationResult {
  if (env.SIGNER_MASTER_KEY) {
    return {
      valid: false,
      error: 'FATAL: SIGNER_MASTER_KEY is deprecated and must not be used. Use SIGNER_KEK, SIGNER_DAEMON_KEY, SIGNER_DAEMON_ECDH_KEY, and SIGNER_UID.'
    }
  }

  const kek = env.SIGNER_KEK
  if (!kek) {
    return {
      valid: false,
      error: 'CRITICAL: SIGNER_KEK environment variable not set'
    }
  }
  if (kek.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(kek)) {
    return {
      valid: false,
      error: 'CRITICAL: SIGNER_KEK must be a 64-character hex string (256 bits)'
    }
  }

  const daemonKey = env.SIGNER_DAEMON_KEY
  if (!daemonKey) {
    return {
      valid: false,
      error: 'CRITICAL: SIGNER_DAEMON_KEY environment variable not set'
    }
  }
  if (daemonKey.length !== 5120 || !/^[0-9a-fA-F]{5120}$/.test(daemonKey)) {
    return {
      valid: false,
      error: 'CRITICAL: SIGNER_DAEMON_KEY must be a 5120-character hex string (ML-DSA-44 secret key)'
    }
  }

  const daemonEcdhKey = env.SIGNER_DAEMON_ECDH_KEY
  if (!daemonEcdhKey || daemonEcdhKey.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(daemonEcdhKey)) {
    return {
      valid: false,
      error: 'CRITICAL: SIGNER_DAEMON_ECDH_KEY environment variable not set or invalid (must be 64-character hex string)'
    }
  }

  const signerUid = env.SIGNER_UID
  if (signerUid) {
    try {
      const daemonPubkey = publicKeyFromSecret('ml-dsa-44', daemonKey)
      const daemonKeyHash = bytesToHex(sha256(daemonPubkey))
      if (signerUid !== daemonKeyHash) {
        return {
          valid: false,
          error: `CRITICAL: SIGNER_UID mismatch! Expected ${signerUid}, got derived ${daemonKeyHash}`
        }
      }
    } catch (e: any) {
      return {
        valid: false,
        error: `CRITICAL: Failed to derive public key from SIGNER_DAEMON_KEY: ${e.message}`
      }
    }
  }

  const platformId = env.VERITY_PLATFORM_ID
  if (!platformId || platformId.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(platformId)) {
    return {
      valid: false,
      error: 'CRITICAL: VERITY_PLATFORM_ID environment variable not set or invalid (must be 64-hex SHA-256)'
    }
  }

  return { valid: true }
}
