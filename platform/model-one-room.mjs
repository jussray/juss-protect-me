// Juss Protect Me — Model One founder room.
// Same core as Model Two (founder-room.mjs), matched to Model One:
// gold branding, and an honest state table for an assets-only site —
// Model One has no Worker and no Shield today, so it claims neither.
import { createFounderRoom } from './founder-room.mjs';

export function createModelOneRoom(opts = {}) {
  return createFounderRoom({
    statsProvider: opts.statsProvider || null,
    brand: {
      bg: '#0a0703',
      glow: '#3a2a10',
      panel: '#171106',
      panel2: '#0e0a05',
      line: '#5c451a',
      accent: '#c9973f',
      accentSoft: '#f3d98b',
      btnInk: '#2a1c05',
    },
    siteRows: [
      {
        name: 'Edge protection — Model One',
        state: 'NOT BUILT',
        note: 'Model One serves static assets only today — no Worker, no Shield. This room\u2019s Worker is its first server layer, added at deploy.',
      },
      {
        name: 'Edge Shield — Model Two',
        state: 'ACTIVE',
        note: 'Runs on Model Two\u2019s Worker (its own routes); managed from that site\u2019s room.',
      },
    ],
    shieldStat: {
      k: 'Edge protection',
      v: '—',
      note: 'Assets-only today; first server layer ships with this room at deploy.',
    },
  });
}
