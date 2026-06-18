'use client';

import { useSyncExternalStore } from 'react';
import {
  getAuditorKeypair,
  getSpendingKeypair,
  subscribeKeys,
  type AuditorKeypair,
  type SpendingKeypair,
} from './keys.js';

/**
 * Reactive access to the in-memory key store (lib/keys.ts). Re-renders when keys
 * change. The store lives in module memory — browser-tab lifetime only, never
 * persisted (invariant #8).
 */
export function useSpendingKeypair(): SpendingKeypair | null {
  return useSyncExternalStore(subscribeKeys, getSpendingKeypair, () => null);
}

export function useAuditorKeypair(): AuditorKeypair | null {
  return useSyncExternalStore(subscribeKeys, getAuditorKeypair, () => null);
}
