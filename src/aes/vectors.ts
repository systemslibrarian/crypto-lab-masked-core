/**
 * Published known-answer vectors. Every value here is copied from a standard,
 * not produced by this code — which is the only thing that makes them a test
 * rather than a tautology.
 *
 * Sources:
 *   FIPS-197  (Advanced Encryption Standard), Figure 7, Appendix A.1, B, C.1
 *   NIST SP 800-38A, Appendix F.1.1 (ECB-AES128.Encrypt)
 */

/** FIPS-197 Figure 7 — the published S-box, to check the derivation against. */
export const FIPS197_SBOX_HEX =
  '637c777bf26b6fc53001672bfed7ab76' +
  'ca82c97dfa5947f0add4a2af9ca472c0' +
  'b7fd9326363ff7cc34a5e5f171d83115' +
  '04c723c31896059a071280e2eb27b275' +
  '09832c1a1b6e5aa0523bd6b329e32f84' +
  '53d100ed20fcb15b6acbbe394a4c58cf' +
  'd0efaafb434d338545f9027f503c9fa8' +
  '51a3408f929d38f5bcb6da2110fff3d2' +
  'cd0c13ec5f974417c4a77e3d645d1973' +
  '60814fdc222a908846eeb814de5e0bdb' +
  'e0323a0a4906245cc2d3ac629195e479' +
  'e7c8376d8dd54ea96c56f4ea657aae08' +
  'ba78252e1ca6b4c6e8dd741f4bbd8b8a' +
  '703eb5664803f60e613557b986c11d9e' +
  'e1f8981169d98e949b1e87e9ce5528df' +
  '8ca1890dbfe6426841992d0fb054bb16';

export interface BlockVector {
  readonly name: string;
  readonly source: string;
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
}

/** Single-block AES-128 encryptions. */
export const BLOCK_VECTORS: readonly BlockVector[] = [
  {
    name: 'FIPS-197 Appendix B',
    source: 'FIPS-197 Appendix B (Cipher Example)',
    key: '2b7e151628aed2a6abf7158809cf4f3c',
    plaintext: '3243f6a8885a308d313198a2e0370734',
    ciphertext: '3925841d02dc09fbdc118597196a0b32',
  },
  {
    name: 'FIPS-197 Appendix C.1',
    source: 'FIPS-197 Appendix C.1 (AES-128)',
    key: '000102030405060708090a0b0c0d0e0f',
    plaintext: '00112233445566778899aabbccddeeff',
    ciphertext: '69c4e0d86a7b0430d8cdb78070b4c55a',
  },
  {
    name: 'SP 800-38A ECB block 1',
    source: 'NIST SP 800-38A F.1.1',
    key: '2b7e151628aed2a6abf7158809cf4f3c',
    plaintext: '6bc1bee22e409f96e93d7e117393172a',
    ciphertext: '3ad77bb40d7a3660a89ecaf32466ef97',
  },
  {
    name: 'SP 800-38A ECB block 2',
    source: 'NIST SP 800-38A F.1.1',
    key: '2b7e151628aed2a6abf7158809cf4f3c',
    plaintext: 'ae2d8a571e03ac9c9eb76fac45af8e51',
    ciphertext: 'f5d3d58503b9699de785895a96fdbaaf',
  },
  {
    name: 'SP 800-38A ECB block 3',
    source: 'NIST SP 800-38A F.1.1',
    key: '2b7e151628aed2a6abf7158809cf4f3c',
    plaintext: '30c81c46a35ce411e5fbc1191a0a52ef',
    ciphertext: '43b1cd7f598ece23881b00e3ed030688',
  },
  {
    name: 'SP 800-38A ECB block 4',
    source: 'NIST SP 800-38A F.1.1',
    key: '2b7e151628aed2a6abf7158809cf4f3c',
    plaintext: 'f69f2445df4f9b17ad2b417be66c3710',
    ciphertext: '7b0c785e27e8ad3f8223207104725dd4',
  },
];

/**
 * FIPS-197 A.1 — two published round keys of the Appendix B expansion. Round 1
 * catches a broken RotWord/SubWord/Rcon; round 10 catches an Rcon that drifts
 * only in the later rounds (Rcon 0x1b and 0x36 are where a naive `rcon <<= 1`
 * without the GF reduction goes wrong, and nothing before round 9 would notice).
 */
export const KEY_SCHEDULE_VECTOR = {
  source: 'FIPS-197 Appendix A.1',
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  round1: 'a0fafe1788542cb123a339392a6c7605',
  round10: 'd014f9a8c9ee2589e13f0cc8b6630ca6',
} as const;

/**
 * FIPS-197 Appendix B round-1 intermediates. These are what the leakage probes
 * read, so they are KATs on the attack surface itself, not only on the cipher's
 * output: `sboxIn` is the first AddRoundKey output and `sboxOut` is the CPA
 * target `SBOX[pt ^ k]`.
 */
export const ROUND1_INTERMEDIATES = {
  source: 'FIPS-197 Appendix B (Round 1 trace)',
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  plaintext: '3243f6a8885a308d313198a2e0370734',
  afterAddRoundKey0: '193de3bea0f4e22b9ac68d2ae9f84808',
  afterSubBytes: 'd42711aee0bf98f1b8b45de51e415230',
  afterShiftRows: 'd4bf5d30e0b452aeb84111f11e2798e5',
  afterMixColumns: '046681e5e0cb199a48f8d37a2806264c',
  afterAddRoundKey1: 'a49c7ff2689f352b6b5bea43026a5049',
} as const;
