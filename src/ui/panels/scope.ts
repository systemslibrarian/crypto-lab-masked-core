/**
 * "Scope" — what is real, what is modelled, and what this page does NOT prove.
 *
 * Act 5 of the brief lives here: the glitch note. It is prose because it has to
 * be. Simulating a glitch would mean inventing a hardware model this lab has no
 * business claiming to have, and a made-up glitch that "proves" masking leaks
 * would be exactly the dishonesty the rest of the page is built to avoid. So
 * the boundary is named instead of faked.
 */
import { BLOCK_VECTORS } from '../../aes/vectors';
import { COST_RATIO_FLOOR, FIXTURE, FROZEN_FIXTURE, OUT_OF_MODEL } from '../../claims/bands';
import { LEAK_AMP, NUM_SAMPLES } from '../../leakage/traces';
import { el, replace, verdict } from '../dom';
import { hexByte } from '../format';

export function renderScope(root: HTMLElement): void {
  const outOfModel = el('ul', { class: 'scope-list', role: 'list' });
  for (const line of OUT_OF_MODEL) outOfModel.appendChild(el('li', { role: 'listitem', text: line }));

  replace(
    root,
    el('h2', { text: 'Scope: what is real here, and what is not' }),
    verdict('info', 'Not production crypto — a teaching demo.', [
      'Nothing on this page protects anything. The key is a published test vector, everything runs in ' +
        'your browser with no backend, and the implementations are written for legibility rather than ' +
        'for deployment — the AES here is not even constant-time, which is a separate side channel of ' +
        'its own.',
    ]),
    el(
      'div',
      { class: 'grid' },
      el(
        'div',
        { class: 'card' },
        el('h3', { text: 'Real' }),
        el(
          'ul',
          { class: 'scope-list', role: 'list' },
          el('li', { role: 'listitem' },
            'AES-128 to FIPS-197, hand-rolled — the S-box is derived from the multiplicative inverse in ' +
              'GF(2^8) plus the affine transform, not pasted in as a table, and the derivation is checked ' +
              'against the published Figure 7 byte for byte.'
          ),
          el('li', { role: 'listitem' },
            `First-order Boolean masking with per-round S-box table recomputation, verified to reproduce ` +
              `all ${BLOCK_VECTORS.length} published ciphertexts across many mask draws.`
          ),
          el('li', { role: 'listitem' },
            'Real Pearson correlation, a real single-bit difference of means, and a real centred-product ' +
              'second-order combination. No result on this page is scripted; every number is computed ' +
              'when you press the button.'
          ),
          el('li', { role: 'listitem' },
            'The two algebraic identities the lab turns on are verified exhaustively — over all 256 masks ' +
              'and all 256 constants — rather than sampled.'
          )
        )
      ),
      el(
        'div',
        { class: 'card' },
        el('h3', { text: 'Simulated' }),
        el(
          'ul',
          { class: 'scope-list', role: 'list' },
          el('li', { role: 'listitem' },
            `The power traces. Each is ${NUM_SAMPLES} samples of a fixed data-independent operation shape, ` +
              `plus ${LEAK_AMP} model unit of leakage per Hamming-weight bit of the register being probed, ` +
              `plus Gaussian noise at sigma ${FIXTURE.noise}. No oscilloscope was involved.`
          ),
          el('li', { role: 'listitem' },
            'The intermediate values inside those traces are NOT simulated: they are read out of the real ' +
              'ciphers on this page. That is the difference between a simulated measurement of a real ' +
              'computation and a fabricated result.'
          ),
          el('li', { role: 'listitem' },
            'The randomness. Masks and noise both come from a seeded mulberry32, so every claim here is ' +
              'reproducible. A real masked implementation must draw masks from a cryptographic generator.'
          )
        )
      )
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'The leakage model, stated plainly' }),
      el(
        'p',
        {},
        'Every measurement on this page assumes power draw tracks the HAMMING WEIGHT of the value in a ' +
          'register, plus independent Gaussian noise, and that a probe sees one register at a time. That ' +
          'is the classical first-order probing model with a Hamming-weight leakage function. It is the ' +
          'model in which first-order Boolean masking is provably secure, and it is the model in which ' +
          'this page measures everything.'
      ),
      el(
        'p',
        {},
        'It is an idealisation. Real silicon does not obey it, and the ways it fails are not small.'
      )
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'Act 5 — the glitch note, and other things outside the model' }),
      el(
        'p',
        {},
        'This is the honest edge of the demonstration, and it matters more than anything the bench shows. ' +
          'A masking scheme can be PROVEN secure in the probing model and still leak at first order in ' +
          'real hardware.'
      ),
      el(
        'p',
        {},
        'The usual culprit is glitches. In combinational logic a signal can settle several times before ' +
          'it stabilises, and during those transient settlings a gate may briefly compute a function of ' +
          'inputs that arrive at different times — including, in a masked circuit, a function of both ' +
          'shares at once. The proof said no single wire depends on the secret; the glitch does not ' +
          'respect the boundary the proof drew. This is exactly why threshold implementations exist: ' +
          'they add a non-completeness property that keeps any share of the circuit independent of at ' +
          'least one input share, so a glitch has nothing to recombine.'
      ),
      verdict('info', 'Not simulated here.', [
        'No glitch, transition or coupling effect is modelled on this page, and none is faked. Inventing ' +
          'a hardware model in order to "demonstrate" a glitch leak would be a made-up result dressed as ' +
          'evidence. The boundary is named instead.',
      ]),
      outOfModel
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'What this page does NOT prove' }),
      el(
        'ul',
        { class: 'scope-list', role: 'list' },
        el('li', { role: 'listitem' },
          'That masking is broken. Act 3 proves one sentence and nothing wider: first-order Boolean ' +
            'masking defeats first-order leakage analysis under the modelled assumptions, and does not ' +
            'protect against higher-order observation. Both halves of that sentence are load-bearing.'
        ),
        el('li', { role: 'listitem' },
          `That masking is useless. It multiplied the attacker's trace requirement by more than ` +
            `${COST_RATIO_FLOOR}x on this bench — around a hundredfold at the recorded numbers — and in ` +
            `the field a trace requirement is a budget, an access window and a risk of detection. A price ` +
            `is not nothing. It is just not a wall.`
        ),
        el('li', { role: 'listitem' },
          `That the Act 4 failure says anything about masking. It does not. Freezing the mask to ` +
            `${hexByte(FROZEN_FIXTURE.pinned)} is a failure of RANDOMNESS with the countermeasure fully ` +
            `intact, and it is deliberately kept as a separate claim from the second-order result.`
        ),
        el('li', { role: 'listitem' },
          'That these trace counts transfer to hardware. They are the trace counts of this noise model. ' +
            'What transfers is the shape: the ratio between orders, and the fact that the ratio is finite.'
        ),
        el('li', { role: 'listitem' },
          'Anything about masking orders above one. Only first-order masking is implemented, so the ' +
            'lab measures attack order 1 against attack order 2 and stops there.'
        )
      )
    ),
    el(
      'details',
      {},
      el('summary', { text: 'How the claims on this page are checked' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'The unit suite runs the real attacks at a fixed seed and asserts each traces-to-disclosure ' +
            'lands inside a recorded band, that each negative claim discloses nothing across its whole ' +
            'schedule, and that the second-order cost ratio stays above its floor. The browser suite ' +
            'asserts the page tells the truth — recomputing the headline numbers from values the page ' +
            'itself printed, by a different route than the renderer took. Both gate the deploy: a ' +
            'failure in either blocks publication.'
        ),
        el(
          'p',
          {},
          'The known-answer vectors come from FIPS-197 (Appendix A.1, B, C.1 and the Figure 7 S-box) and ' +
            'NIST SP 800-38A Appendix F.1.1. They are copied from the standards, which is the only thing ' +
            'that makes them a test rather than a restatement of this code.'
        )
      )
    )
  );
}
