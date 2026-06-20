'use client';

/**
 * Minimal client-side note store (FIN-027 / FIN-019-lite). A real wallet remembers
 * the openings of the notes IT created so it can later spend them; this is that,
 * backed by localStorage. After a successful in-browser `shield`, the new note's
 * opening (value/rho/r_note/owner) + its leaf index are saved here, so a later
 * `unshield`/`transfer` can find and spend it — making the demo repeatable without
 * a full indexer.
 *
 * SECURITY (invariant #8): these are demo openings; in a real wallet the store is
 * encrypted at rest. Nothing here is sent to any backend.
 */

const KEY = 'finnes.shielded-notes.v1';

export interface StoredNote {
  /** On-chain leaf index where this note's commitment was inserted. */
  readonly leafIndex: number;
  readonly assetId: string; // decimal Fr
  readonly value: string; // raw units
  readonly ownerPk: string;
  readonly ownerSk: string;
  readonly rho: string;
  readonly rNote: string;
}

export function loadStoredNotes(): StoredNote[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? '[]');
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

export function saveStoredNote(n: StoredNote): void {
  if (typeof localStorage === 'undefined') return;
  const all = loadStoredNotes().filter((x) => x.leafIndex !== n.leafIndex);
  all.push(n);
  all.sort((a, b) => a.leafIndex - b.leafIndex);
  localStorage.setItem(KEY, JSON.stringify(all));
}
