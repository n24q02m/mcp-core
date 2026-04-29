/**
 * Bridge auto-respawn parity tests (D8, Task 1.12).
 *
 * Mirrors ``packages/core-py/tests/transport/test_auto_respawn.py``. Covers
 * the ``MAX_RESPAWN_PER_CALL_ID`` constant and the ``BridgeAutoRespawn``
 * tracker. Lock-acquire / spawn / wait-ready primitives in core-ts are
 * exercised by the integration suite -- here we focus on the cross-language
 * parity surface that callers depend on.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

import { BridgeAutoRespawn, MAX_RESPAWN_PER_CALL_ID } from '../../src/transport/smart-stdio.js'

describe('bridge auto-respawn', () => {
  beforeEach(() => {
    vi.useRealTimers()
  })

  it('exports the per-call-id cap matching core-py', () => {
    expect(MAX_RESPAWN_PER_CALL_ID).toBe(1)
  })

  it('tracks call ids independently and caps respawn count per id', () => {
    const tracker = new BridgeAutoRespawn()

    expect(tracker.canRespawn('call-1')).toBe(true)
    tracker.markRespawned('call-1')
    // Second attempt within the TTL window is blocked for the same call id.
    expect(tracker.canRespawn('call-1')).toBe(false)
    // Different call ids stay independent.
    expect(tracker.canRespawn('call-2')).toBe(true)
  })

  it('expires tracking entries after 5 minutes', () => {
    const tracker = new BridgeAutoRespawn()
    vi.useFakeTimers()
    vi.setSystemTime(new Date(1_700_000_000_000))

    tracker.markRespawned('call-1')
    expect(tracker.canRespawn('call-1')).toBe(false)

    // Advance 6 minutes -- the entry should fall out of the tracking window.
    vi.setSystemTime(new Date(1_700_000_000_000 + 6 * 60_000))
    expect(tracker.canRespawn('call-1')).toBe(true)

    vi.useRealTimers()
  })
})
