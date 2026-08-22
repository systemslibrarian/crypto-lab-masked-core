/**
 * "Masked AES" — the construction under measurement, and the proof it is still
 * AES.
 *
 * Two things have to be true before any security claim is worth discussing, and
 * both are computed live here rather than asserted:
 *   1. the recomputed table really does satisfy S'[x ^ mIn] = SBOX[x] ^ mOut,
 *      checked across all 256 inputs on every redraw;
 *   2. the masked cipher's output, once unmasked, is byte-for-byte the
 *      published FIPS-197 ciphertext.
 *
 * The panel also shows the masked state BEFORE unmasking, because that is the
 * value a memory probe would find, and seeing that it looks nothing like the
 * ciphertext is the point.
 */
import { bytesToHex, encryptBlock, hexToBytes, SBOX } from '../../aes/aes';
import { BLOCK_VECTORS } from '../../aes/vectors';
import { Rng } from '../../leakage/rng';
import { encryptMasked, recomputeSboxTable, type MaskSource } from '../../mask/maskedAes';
import { el, kv, labelled, pill, replace, scroller, verdict } from '../dom';
import { hexByte } from '../format';

export function renderConstruction(root: HTMLElement): void {
  let vectorIndex = 0;
  let seed = 4;
  let frozen = false;

  const vectorSelect = el('select', {}) as HTMLSelectElement;
  BLOCK_VECTORS.forEach((v, i) => {
    vectorSelect.appendChild(el('option', { value: String(i), text: v.name }));
  });

  const modeGroup = el('div', { class: 'seg', role: 'group', 'aria-label': 'Mask source' });
  const freshBtn = el('button', {
    type: 'button',
    class: 'seg-btn',
    'aria-pressed': 'true',
    text: 'Fresh mask each round',
  });
  const frozenBtn = el('button', {
    type: 'button',
    class: 'seg-btn',
    'aria-pressed': 'false',
    text: 'Frozen mask 0x01',
  });
  modeGroup.appendChild(freshBtn);
  modeGroup.appendChild(frozenBtn);

  const redrawBtn = el('button', { type: 'button', text: 'Draw new masks' });
  const tableOut = el('div', { id: 'con-table' });
  const runOut = el('div', { id: 'con-run' });
  const katOut = el('div', { id: 'con-kat' });

  function paint(): void {
    const v = BLOCK_VECTORS[vectorIndex];
    const pt = hexToBytes(v.plaintext);
    const key = hexToBytes(v.key);
    const source: MaskSource = frozen ? { kind: 'frozen', constant: 0x01 } : { kind: 'fresh' };
    const result = encryptMasked(pt, key, new Rng(seed), source);
    const { mIn, mOut } = result.roundMasks[0];

    // ── The recomputed table, and its defining property checked live ────────
    const table = recomputeSboxTable(mIn, mOut);
    let mismatches = 0;
    for (let x = 0; x < 256; x++) if (table[(x ^ mIn) & 0xff] !== (SBOX[x] ^ mOut)) mismatches++;

    const rows = el('tbody');
    for (let x = 0x2a; x < 0x2a + 6; x++) {
      rows.appendChild(
        el(
          'tr',
          {},
          el('td', { class: 'num', text: hexByte(x) }),
          el('td', { class: 'num', text: hexByte(SBOX[x]) }),
          el('td', { class: 'num', text: hexByte(x ^ mIn) }),
          el('td', { class: 'num', text: hexByte(table[(x ^ mIn) & 0xff]) }),
          el('td', { class: 'num', text: hexByte(SBOX[x] ^ mOut) })
        )
      );
    }

    replace(
      tableOut,
      kv([
        ['Round 1 input mask mIn', hexByte(mIn)],
        ['Round 1 output mask mOut', hexByte(mOut)],
        ['Table entries rebuilt', '256 — once per round, which is what masking costs'],
      ]),
      scroller(
        'Six entries of the recomputed masked S-box table',
        el(
          'table',
          {},
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { class: 'num', text: 'x' }),
              el('th', { class: 'num', text: 'SBOX[x]' }),
              el('th', { class: 'num', text: 'x XOR mIn' }),
              el('th', { class: 'num', text: "S'[x XOR mIn]" }),
              el('th', { class: 'num', text: 'SBOX[x] XOR mOut' })
            )
          ),
          rows
        )
      ),
      verdict(
        mismatches === 0 ? 'pass' : 'fail',
        mismatches === 0 ? 'Table property holds.' : 'Table property broken.',
        [
          mismatches === 0
            ? `The last two columns agree on every one of the 256 inputs, not just the six shown. That is the whole trick: feed the table a value masked with mIn and it hands back the S-box output masked with mOut, and the unmasked value x never exists in any register.`
            : `${mismatches} of 256 entries disagree, so the masked cipher would not produce AES.`,
        ]
      )
    );

    // ── One masked encryption, end to end ───────────────────────────────────
    const plain = encryptBlock(pt, key);
    const maskedHex = bytesToHex(result.maskedStateBeforeUnmask);
    const correct = bytesToHex(result.ciphertext) === v.ciphertext;
    const matchesPlain = bytesToHex(result.ciphertext) === bytesToHex(plain);

    replace(
      runOut,
      kv([
        ['Plaintext', v.plaintext],
        ['Key', v.key],
        ['Masked state before unmasking', maskedHex],
        ['Accumulated mask', bytesToHex(result.finalMask)],
        ['Unmasked output', bytesToHex(result.ciphertext)],
        ['Published ciphertext', `${v.ciphertext}  (${v.source})`],
      ]),
      verdict(
        correct && matchesPlain ? 'pass' : 'fail',
        correct && matchesPlain ? 'Byte-for-byte identical.' : 'Ciphertext mismatch.',
        [
          correct && matchesPlain
            ? `The masked implementation produced the published ciphertext, and the plain implementation produced the same thing. Note the row above it: the state actually sitting in memory before the final unmask is ${maskedHex.slice(0, 8)}…, which is not the ciphertext and not anything derivable from it without the mask.`
            : `The masked implementation did not reproduce the published ciphertext. The construction is broken.`,
        ]
      ),
      frozen
        ? verdict('alarm', 'Still correct — and no longer protecting anything.', [
            'With the mask frozen to a constant, the ciphertext is exactly as right as before. ' +
              'Correctness is not the tell. Nothing in this panel can distinguish a working ' +
              'countermeasure from a broken one; that takes the bench.',
          ])
        : null
    );

    // ── Every published vector, both ways ───────────────────────────────────
    const katRows = el('tbody');
    let passed = 0;
    for (const kat of BLOCK_VECTORS) {
      const p = hexToBytes(kat.plaintext);
      const k = hexToBytes(kat.key);
      const plainOk = bytesToHex(encryptBlock(p, k)) === kat.ciphertext;
      const maskedOk =
        bytesToHex(encryptMasked(p, k, new Rng(seed + 1), source).ciphertext) === kat.ciphertext;
      if (plainOk && maskedOk) passed++;
      katRows.appendChild(
        el(
          'tr',
          {},
          el('td', { text: kat.name }),
          el('td', { text: kat.source }),
          el('td', {}, pill(plainOk ? 'ok' : 'bad', plainOk ? 'PASS' : 'FAIL')),
          el('td', {}, pill(maskedOk ? 'ok' : 'bad', maskedOk ? 'PASS' : 'FAIL'))
        )
      );
    }
    replace(
      katOut,
      scroller(
        'Known-answer vectors, plain and masked',
        el(
          'table',
          {},
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { text: 'Vector' }),
              el('th', { text: 'Source' }),
              el('th', { text: 'Plain AES' }),
              el('th', { text: 'Masked AES' })
            )
          ),
          katRows
        )
      ),
      verdict(
        passed === BLOCK_VECTORS.length ? 'pass' : 'fail',
        `${passed} / ${BLOCK_VECTORS.length} vectors.`,
        [
          passed === BLOCK_VECTORS.length
            ? 'Both implementations reproduce every published ciphertext. The unit suite runs the same check across 64 different mask draws per vector, and over 200 random blocks, so this is not one lucky mask.'
            : 'At least one vector failed; nothing below this point should be trusted.',
        ]
      )
    );
  }

  vectorSelect.addEventListener('change', () => {
    vectorIndex = Number(vectorSelect.value);
    paint();
  });
  redrawBtn.addEventListener('click', () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    paint();
  });
  freshBtn.addEventListener('click', () => {
    frozen = false;
    freshBtn.setAttribute('aria-pressed', 'true');
    frozenBtn.setAttribute('aria-pressed', 'false');
    paint();
  });
  frozenBtn.addEventListener('click', () => {
    frozen = true;
    freshBtn.setAttribute('aria-pressed', 'false');
    frozenBtn.setAttribute('aria-pressed', 'true');
    paint();
  });

  replace(
    root,
    el('h2', { text: 'The construction: first-order Boolean masking of AES-128' }),
    el(
      'p',
      { class: 'lede' },
      'Every intermediate is carried as a pair — the value XOR a mask, and the mask. ' +
        'AddRoundKey, ShiftRows and MixColumns are all linear over GF(2), so they pass a mask ' +
        'straight through: apply them to both halves and the pair still represents the same state. ' +
        'The S-box is the one non-linear step, and it is where the whole cost of masking lands.'
    ),
    el(
      'div',
      { class: 'controls' },
      labelled('con-vector', 'Known-answer vector', vectorSelect),
      el('div', { class: 'field' }, el('span', { class: 'group-label', text: 'Mask source' }), modeGroup),
      el('div', { class: 'field' }, redrawBtn)
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'The recomputed S-box table' }),
      el(
        'p',
        {},
        'You cannot look up a masked value in the ordinary S-box: SBOX[x XOR m] has nothing to do ' +
          'with SBOX[x]. So the implementation rebuilds a whole 256-entry table each round, one that ' +
          'takes a value masked with mIn and returns the S-box output masked with mOut.'
      ),
      tableOut
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'One masked encryption, end to end' }),
      runOut
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'Known-answer tests' }),
      katOut
    ),
    el(
      'details',
      {},
      el('summary', { text: 'Why re-masking is the dangerous line, and how it is written here' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'Each round shares one table across all sixteen bytes, so every byte has to be moved onto ' +
            'that round’s input mask first. The obvious way to write it is a first-order break:'
        ),
        el('p', { class: 'mono' }, 'state[j] = state[j] ^ mask[j] ^ mIn      // WRONG'),
        el(
          'p',
          {},
          'Evaluated left to right, the intermediate state[j] ^ mask[j] is the UNMASKED byte, sitting ' +
            'in a register for one instruction. A first-order probe would read it straight off. The fix ' +
            'is to form the difference in the mask domain first, where nothing depends on the secret:'
        ),
        el('p', { class: 'mono' }, 'd = mask[j] ^ mIn ;  state[j] = state[j] ^ d      // correct'),
        el(
          'p',
          {},
          'This lab keeps that as its own named function, `remaskDelta`, precisely so the ordering ' +
            'cannot be fumbled by an edit. It is a good illustration of why masking is hard to get ' +
            'right in practice even when the scheme on paper is simple.'
        )
      )
    ),
    el(
      'details',
      {},
      el('summary', { text: 'Why the linear layers are free' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'MixColumns is a matrix multiply over GF(2^8) whose additions are XOR, so ' +
            'MixColumns(x XOR m) equals MixColumns(x) XOR MixColumns(m). ShiftRows is a permutation, ' +
            'and permuting the masked state and the mask identically preserves the pairing. ' +
            'AddRoundKey XORs in a value the mask knows nothing about, so it does not touch the mask ' +
            'at all. The unit suite measures both identities over pseudo-random states rather than ' +
            'asserting them here.'
        ),
        el(
          'p',
          {},
          'That is the whole reason the S-box needs special treatment and nothing else does — and ' +
            'the reason masked AES costs roughly what it costs: 256 table writes per round, on top of ' +
            'a round that would otherwise be sixteen lookups.'
        )
      )
    )
  );

  paint();
}
