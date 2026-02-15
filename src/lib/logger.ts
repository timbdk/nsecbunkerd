/**
 * Structured Logger for Event Signing Service
 *
 * Provides consistent, structured logging for:
 * - Production audit trail (signing operations)
 * - Development terminal visibility
 * - Test-runner log capture
 *
 * Uses namespaced debug modules for filtering.
 */

import createDebug from 'debug'

// ============================================================================
// NAMESPACED LOGGERS
// ============================================================================

// Core operation logs (always shown in development)
export const log = {
  // Daemon lifecycle
  daemon: createDebug('signer:daemon'),

  // Admin interface commands
  admin: createDebug('signer:admin'),

  // Per-key backend operations
  backend: createDebug('signer:backend'),

  // ACL/authorization decisions
  acl: createDebug('signer:acl'),

  // Key operations (encrypt, decrypt, store)
  keys: createDebug('signer:keys'),

  // HTTP endpoints
  http: createDebug('signer:http'),

  // Signing operations (audit trail)
  signing: createDebug('signer:signing')
}

// ============================================================================
// AUDIT LOGGER
// ============================================================================

/**
 * Structured audit log for signing operations.
 * These logs are critical for production audit trail.
 */
export interface SigningAuditEvent {
  timestamp: string
  keyName: string
  userPubkey?: string
  clientPubkey: string
  method: string
  eventKind?: number
  allowed: boolean
  reason?: string
}

export function auditSigningRequest(event: SigningAuditEvent): void {
  const entry = {
    ...event,
    timestamp: event.timestamp || new Date().toISOString()
  }

  // Always log to console in JSON format for production log aggregation
  console.log(JSON.stringify({ type: 'SIGNING_AUDIT', ...entry }))

  // Also log to debug namespace for development
  if (entry.allowed) {
    log.signing(`✅ ${entry.method} allowed for ${entry.clientPubkey.slice(0, 16)}... on ${entry.keyName}`)
  } else {
    log.signing(`❌ ${entry.method} denied for ${entry.clientPubkey.slice(0, 16)}... on ${entry.keyName}: ${entry.reason}`)
  }
}

// ============================================================================
// LIFECYCLE LOGGER
// ============================================================================

export function logStartup(message: string, data?: Record<string, any>): void {
  const emoji = message.includes('Error') || message.includes('CRITICAL') ? '❌' : '✅'
  console.log(`${emoji} ${message}`, data ? JSON.stringify(data) : '')
  log.daemon(message, data)
}

export function logError(namespace: keyof typeof log, message: string, error?: any): void {
  console.error(`❌ ${message}`, error?.message || error || '')
  log[namespace](`ERROR: ${message}`, error)
}

// ============================================================================
// ENABLE DEBUG IN DEVELOPMENT
// ============================================================================

// Auto-enable all signer logs in development/testing
if (process.env.NODE_ENV !== 'production') {
  // Enable all signer namespaces if DEBUG not already set
  if (!process.env.DEBUG) {
    createDebug.enable('signer:*')
  }
}
