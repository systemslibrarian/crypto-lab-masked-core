# Masked Core

**Correlation power analysis pulls an AES-128 key byte out of a few hundred simulated
traces. First-order Boolean masking flattens the same attack to nothing. Then a
second-order combining function pulls the same byte back out.** Masking is a price, not a
wall — and this lab measures the price.

> **Not production crypto — a teaching demo.** The AES-128, the masking, and the statistics
> are real; the power traces are **simulated** from the real ciphers' real intermediate
> values. Everything runs in your browser with no backend, against a published test-vector
> key. See [What Can Go Wrong](#what-can-go-wrong) and the in-page Scope tab for exactly
> what is real, what is modelled, and what this does **not** prove.

## What It Is

An interactive bench for the countermeasure itself. The catalog already teaches defences in
several places — Nonce Guard's misuse resistance, Downgrade Wire's transcript binding,
Timing Side-Channel's constant-time compare, KEM Trap's key confirmation, Protocol Compose's
Encrypt-then-MAC. What it has not done before is make a countermeasure the object under
measurement and then break it.

The construction is **first-order Boolean masking of AES-128**. Every intermediate `x` is
carried as the pair `(x ^ m, m)` for a fresh random mask. AddRoundKey, ShiftRows and
MixColumns are GF(2)-linear, so a mask passes straight through them; the S-box is not, so
the implementation rebuilds a **masked S-box table** each round, `S'[a] = SBOX[a ^ mIn] ^ mOut`,
and the unmasked value never exists in any register.

Everything cryptographic is hand-rolled so it can be read:

- **AES-128 to FIPS-197** — the S-box is *derived* from the multiplicative inverse in
  GF(2⁸) plus the AES affine transform, not pasted in as a magic table, and the derivation
  is checked byte-for-byte against the published Figure 7. Real key schedule, real round
  function, validated against FIPS-197 Appendix B and C.1 and NIST SP 800-38A F.1.1.
- **Real masking** — table recomputation per round, with re-masking written so it cannot
  transiently unmask (the mask-domain delta is computed first, in its own named function).
  The masked cipher reproduces every published ciphertext across hundreds of mask draws.
- **Real statistics** — Pearson correlation (Brier–Clavier–Olivier 2004), the single-bit
  difference of means (Kocher–Jaffe–Jun 1999), and the centred-product second-order
  combination (Chari et al. 1999; Messerges 2000; analysed by Prouff–Rivain–Bévan 2009).
  The CPA and DPA machinery is carried over from this suite's
  [Power Trace](https://github.com/systemslibrarian/crypto-lab-power-trace) lab so the two
  benches are directly comparable.
- **Simulated traces** — generated from the real ciphers' real intermediates plus a
  Hamming-weight leakage term and Gaussian noise. Not captured from silicon.

**Security model.** The classical first-order probing model with a Hamming-weight leakage
function: power tracks the number of 1-bits in one register at a time, plus independent
Gaussian noise. That is the model in which first-order Boolean masking is provably secure,
and it is the model in which everything here is measured. It is an idealisation, stated
persistently on the page rather than buried — see [What Can Go Wrong](#what-can-go-wrong).

### The mathematics, in three identities

All three are verified **exhaustively** in the test suite — over all 256 masks, all 256
constants, all 8 bits — rather than sampled, and the in-page derivations are behind
disclosures so a newcomer can skip them and an expert can check them.

1. **Why one probe learns nothing.** `m -> v ^ m` is a bijection, so `{v ^ m}` is the whole
   byte space for every `v`. Both shares have identical marginal distributions whatever the
   secret is, so any statistic of one share alone carries zero information about `v`.
2. **Why two probes give it back.** Centre both leakages on 4 and multiply:
   `E[(HW(m) - 4)(HW(v ^ m) - 4)] = -(1/2)(HW(v) - 4)`. The centred product is an unbiased,
   exactly linear — and *negative* — estimator of `HW(v)`. Masking did not remove the
   secret; it moved it from the first moment to the second.
3. **What a frozen mask leaves behind.** With the mask pinned to a constant `c`,
   `rho(HW(v ^ c), HW(v)) = 1 - HW(c)/4` exactly. A low-weight constant leaves the
   correlation nearly intact; a **balanced** constant drives it to *zero*, so the attack
   reports nothing while the protection is entirely gone.

## Exhibits

1. **The split** — the headline mechanism, shown rather than asserted. Drag a secret byte
   across its whole range and watch the two shares' Hamming-weight distributions *not move*;
   watch the joint distribution tilt the instant the secret changes, with a slope of exactly
   `1 - HW(v)/4`. Both curves are computed over all 256 masks with no sampling, and the
   closed form is drawn on top of the measurement so they can be compared rather than
   believed.
2. **Masked AES** — the construction under measurement. The recomputed table with its
   defining property checked live across all 256 inputs; one masked encryption end to end,
   showing the masked state in memory beside the ciphertext it is not; and every published
   vector run through both implementations. Switch the mask source to frozen and the
   ciphertext stays perfectly correct — correctness is not the tell.
3. **The bench (Acts 1–3)** — one attack, three protections, three distinguishers, and a
   switch you can flip. *Act 1*: first-order CPA against plain AES-128 recovers key byte 0
   in a couple of hundred traces. *Act 2*: **the same attack**, with masking on, never
   converges however many traces you give it. *Act 3*: combine the mask register with the
   masked S-box output using the centred product and the key comes back — with the negative
   sign identity 2 predicts. Every control stays live afterwards, so you can pair the wrong
   samples, attack an idle cycle, or feed it a malformed key and watch it refuse.
4. **Frozen mask (Act 4)** — the countermeasure intact, the randomness gone. The default
   constant is *pinned* to `0x01` and its predicted correlation printed beside the measured
   one. Switch it to a balanced constant and the Hamming-weight attack falls silent while
   the single-bit attack on the same traces keeps recovering the key.
5. **Cost** — the recorded traces-to-disclosure band for every claim, the multiplier
   between orders, and a button that reproduces any claim in your browser on the same
   schedule the band was recorded against.
6. **Scope (Act 5)** — the leakage model stated plainly, the glitch note, and the list of
   things this page does not prove.

## When to Use It

- **To understand why masking is deployed** — it is the countermeasure smartcards, TPMs and
  secure elements are certified on, and Act 3 shows precisely what it buys: a large,
  finite, measurable increase in the attacker's trace budget.
- **To understand why masking is hard to get right** — the re-masking ordering trap and the
  frozen-mask act are both failures that leave the countermeasure looking perfect in code
  review and in a correctness test.
- **To calibrate an intuition about attack orders** — a `d`-th order scheme needs an
  order-`(d+1)` attack, and this lab measures the 1-versus-2 step honestly.
- **Do NOT use this code in anything that protects a secret.** The AES here is a teaching
  implementation with data-dependent table lookups (a timing side channel of its own), the
  masks come from a seeded non-cryptographic PRNG, and the masking is first-order only with
  no glitch resistance. It is written to be read, not deployed.
- **Do NOT read the trace counts as hardware numbers.** They are the trace counts of this
  noise model. What transfers is the ratio between orders, and the fact that it is finite.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-masked-core/>**

Run the three acts from the guided presets, then leave the script: raise the noise, move
the attacked sample, pair the mask register with the wrong partner, freeze the mask to a
balanced constant, and reproduce any recorded claim in your own browser.

## What Can Go Wrong

The interesting failures here are not bugs in the cipher. They are the ways a correct
countermeasure stops protecting anything.

- **Higher-order observation.** This is the headline. First-order masking defeats
  first-order leakage analysis under the modelled assumptions, and does not protect against
  an attacker who can combine two samples. Act 3 proves exactly that sentence and nothing
  broader.
- **Broken randomness.** Act 4. Freeze the mask to a constant — an RNG that was never
  seeded, a mask computed once at boot, a test harness left in a shipping build — and the
  masked value becomes a deterministic function of the unmasked one. Every line of the
  countermeasure is still there and the ciphertext is still correct. **This is a separate
  lesson from Act 3**, and the lab deliberately keeps the two claims apart: it is a failure
  of randomness, not of masking.
- **The balanced-constant trap.** A frozen constant of Hamming weight 4 drives the
  Hamming-weight correlation to *exactly* zero. An attack that reports nothing looks
  identical to a countermeasure that is working. This is why the lab pins its fixture and
  leads Act 4 with a single-bit distinguisher, which recovers the key for *any* fixed
  constant.
- **Re-masking that transiently unmasks.** Writing `state ^ mask ^ mIn` left to right puts
  the unmasked byte in a register for one instruction. The scheme on paper is untouched and
  a first-order probe reads the secret straight off.
- **Glitches — and this is the one that matters most.** A masking scheme can be *proven*
  secure in the probing model and still leak at first order in real hardware, because a
  combinational glitch can transiently compute a function of both shares at once. The proof
  said no single wire depends on the secret; the glitch does not respect the boundary the
  proof drew. This is why **threshold implementations** exist. **No glitch is simulated
  here, and none is faked** — inventing a hardware model in order to "demonstrate" a glitch
  leak would be a made-up result dressed as evidence, so the boundary is named instead.
- **Also outside the model:** transitions (real registers leak the Hamming *distance*
  between successive values) and coupling between neighbouring wires, either of which can
  recombine shares the probing model treats as separate; imperfect randomness short of a
  frozen mask; and masking orders above one.

## Real-World Usage

Boolean masking is the mainstream software countermeasure against differential power
analysis, and it is what smartcard, TPM and secure-element evaluations under Common
Criteria and EMVCo are largely arguing about. It is also why hardware people talk about
**threshold implementations** and **domain-oriented masking**: those exist because the
probing-model proof this lab measures does not survive contact with combinational glitches.

The second-order attack here is the standard published one. Chari, Jutla, Rao and Rohatgi
established the theory of higher-order attacks against secret-sharing countermeasures in
1999; Messerges introduced the practical combining functions in 2000; Prouff, Rivain and
Bévan gave the statistical analysis of the centred product in 2009, which is where the
`-(1/2)(HW(v) - 4)` identity on this page comes from. The trace-count blow-up between
orders is the whole reason masking is worth deploying despite being breakable — and the
whole reason it is not sufficient on its own.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-masked-core.git
cd crypto-lab-masked-core
npm install
npm run dev            # http://localhost:5173/crypto-lab-masked-core/
```

```bash
npm test               # unit suite: spec KATs, exhaustive identities, seeded band gate
npm run build          # typecheck + production build
npx playwright install chromium
npm run test:a11y      # the WCAG 2.1 AA gate, against the production build
npm run test:claims    # the claims suite: does the page tell the truth?
```

## Related Demos

- **[Power Trace](https://github.com/systemslibrarian/crypto-lab-power-trace)** — the
  unprotected side of this story, and the origin of the CPA/DPA machinery reused here.
  Start there if correlation power analysis is new to you.
- **[Timing Side-Channel](https://github.com/systemslibrarian/crypto-lab-timing-side-channel)**
  and **[Timing Oracle](https://github.com/systemslibrarian/crypto-lab-timing-oracle)** —
  the other classical channel, and a countermeasure (constant-time compare) taught as part
  of the fix rather than as the subject.
- **[Nonce Guard](https://github.com/systemslibrarian/crypto-lab-nonce-guard)** — another
  countermeasure under load, and another lab where the failure is about randomness rather
  than about the primitive.
- **[Entropy Collapse](https://github.com/systemslibrarian/crypto-lab-entropy-collapse)** —
  what else breaks when the random numbers stop being random.

## Build & Verify

Vite + TypeScript, no runtime dependencies, static to GitHub Pages.

**Unit suite — 139 tests across 11 files (`npm test`), all passing.**

| File | What it proves |
|---|---|
| `src/aes/aes.test.ts` | FIPS-197 KATs: the derived S-box against published Figure 7, round keys 1 and 10 from Appendix A.1, the Appendix B round-1 trace step by step, six single-block ciphertexts from Appendix B, C.1 and SP 800-38A F.1.1, and the linearity of MixColumns and ShiftRows measured rather than assumed |
| `src/mask/maskedAes.test.ts` | the masked cipher reproduces every published ciphertext across 64 mask draws each and 200 random blocks; the recomputed table's defining property across all 256 inputs; the round-1-only bench path produces identical probes to the full ten-round cipher |
| `src/mask/combining.test.ts` | the three identities, exhaustively — the marginals, the centred product (checked two independent ways), the frozen-mask correlation over all 256 constants, and the single-bit difference over all 256 constants × 8 bits |
| `src/claims/bands.test.ts` | the seeded traces-to-disclosure band gate, and the cost-ratio floor |
| `src/attack/*.test.ts` | the streaming accumulators against direct two-pass computations; the second-order prefix algebra against a naive re-implementation; the stability rule on a scripted rank sequence |
| `src/leakage/traces.test.ts` | the bench is deterministic, protections are a controlled experiment, and unmasking a noiseless masked trace reproduces the unprotected one exactly |

**Known-answer vector sources** are in `src/aes/vectors.ts`, copied from the standards
(FIPS-197 Figure 7, A.1, B, C.1; NIST SP 800-38A F.1.1) rather than generated by this code —
which is the only thing that makes them a test rather than a restatement.

**The statistical claims are gated deterministically.** Failing the build when "the
second-order attack stops working" would be flaky: a statistical attack near its disclosure
threshold varies run to run. Instead the PRNG seed and the checkpoint schedule are pinned
and each claim records a *band* the traces-to-disclosure must land in
(`src/claims/bands.ts`). Bands are wide enough that six different seeds all land inside
them and narrow enough that a broken model cannot. If this masked implementation suddenly
*resisted* second-order CPA in this model, the model would have broken — nothing about the
masking would have improved — and a band violation is what surfaces that.

**Accessibility is enforced, not aspirational.** `@axe-core/playwright` scans the
*production build* for zero WCAG 2.1 A/AA violations at 1280px and at 380px, across every
state the lab renders — including all four verdict tones, four different refusal paths, the
retired-verdict states, every disclosure, three hover states and three focus rings. The gate
also computes contrast arithmetically (axe declines to judge `color-mix()` fills, which is
what every verdict on this page is made of), asserts axe's `incomplete` bucket rather than
only `violations`, and carries a non-text-contrast oracle ratcheted against an empty
baseline. Both it and the claims suite block the Pages deploy.

## Performance

Everything runs in one browser tab with no worker. A 30,000-trace second-order attack —
generating the traces from the real masked cipher, accumulating five sums per key guess, and
reading the correlation at 25 checkpoints — takes well under a second on a laptop; the
120,000-trace claim reproduction takes a few seconds. Traces are streamed in 3,000-trace
chunks and never stored, so the page yields to the browser between chunks and memory is flat
regardless of the trace count.

The second-order attack's prefix algebra is what makes the convergence curve affordable.
Re-centring on each checkpoint's own means naively needs one pass per checkpoint; expanding
the centred product against the prefix means turns all of them into fixed combinations of
raw running sums, so the exact curve comes out of a single pass. `secondOrder.test.ts`
checks that against a direct two-pass implementation at six different prefix lengths rather
than taking the algebra on trust.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
