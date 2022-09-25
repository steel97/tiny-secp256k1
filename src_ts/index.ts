import { compare } from "uint8array-tools";
import * as validate from "./validate.js";
import wasm from "./wasm_loader.js";

const WASM_BUFFER = new Uint8Array(wasm.memory.buffer);
const WASM_PRIVATE_KEY_PTR = wasm.PRIVATE_INPUT.value;
const WASM_PUBLIC_KEY_INPUT_PTR = wasm.PUBLIC_KEY_INPUT.value;
const WASM_PUBLIC_KEY_INPUT_PTR2 = wasm.PUBLIC_KEY_INPUT2.value;
const WASM_X_ONLY_PUBLIC_KEY_INPUT_PTR = wasm.X_ONLY_PUBLIC_KEY_INPUT.value;
const WASM_X_ONLY_PUBLIC_KEY_INPUT2_PTR = wasm.X_ONLY_PUBLIC_KEY_INPUT2.value;
const WASM_TWEAK_INPUT_PTR = wasm.TWEAK_INPUT.value;
const WASM_HASH_INPUT_PTR = wasm.HASH_INPUT.value;
const WASM_EXTRA_DATA_INPUT_PTR = wasm.EXTRA_DATA_INPUT.value;
const WASM_SIGNATURE_INPUT_PTR = wasm.SIGNATURE_INPUT.value;

// veil
const WASM_KI_OUTPUT_PTR = wasm.KI_OUTPUT.value;
const WASM_PK_INPUT_PTR = wasm.PK_INPUT.value;
const WASM_SK_INPUT_PTR = wasm.SK_INPUT.value;

const WASM_BLIND_OUTPUT_PTR = wasm.BLIND_OUTPUT.value;
const WASM_MESSAGE_OUTPUT_PTR = wasm.MESSAGE_OUTPUT.value;
const WASM_NONCE_OUTPUT_PTR = wasm.NONCE_OUTPUT.value;
const WASM_COMMIT_PTR = wasm.COMMIT.value;
const WASM_PROOF_PTR = wasm.PROOF.value;
const WASM_PROOFRESULT_PTR = wasm.PROOFRESULT.value;

// new buffers

// BLINDS - big array
const WASM_BLINDS_PTR = wasm.BLINDS.value;
// M_INPUT - big array
const WASM_M_INPUT_PTR = wasm.M_INPUT.value;
// PCM_IN - big array
const WASM_PCM_IN_PTR = wasm.PCM_IN.value;
// PCM_OUT - big array
const WASM_PCM_OUT_PTR = wasm.PCM_OUT.value;
// KI_OUTPUT - big array
const WASM_KI_BIG_OUTPUT_PTR = wasm.KI_BIG_OUTPUT.value;
// PC_OUTPUT - big array
const WASM_PC_OUTPUT_PTR = wasm.PC_OUTPUT.value;
// PS_OUTPUT - big array
const WASM_PS_OUTPUT_PTR = wasm.PS_OUTPUT.value;
// PREIMAGE_INPUT - 32 bytes,
const WASM_PREIMAGE_INPUT_PTR = wasm.PREIMAGE_INPUT.value;
// SKS_INPUT - big array
const WASM_SKS_INPUT_PTR = wasm.SKS_INPUT.value;
// PKS_INPUT - big array
const WASM_PKS_INPUT_PTR = wasm.PKS_INPUT.value;

// end


// end

const PRIVATE_KEY_INPUT = WASM_BUFFER.subarray(
  WASM_PRIVATE_KEY_PTR,
  WASM_PRIVATE_KEY_PTR + validate.PRIVATE_KEY_SIZE
);
const PUBLIC_KEY_INPUT = WASM_BUFFER.subarray(
  WASM_PUBLIC_KEY_INPUT_PTR,
  WASM_PUBLIC_KEY_INPUT_PTR + validate.PUBLIC_KEY_UNCOMPRESSED_SIZE
);
const PUBLIC_KEY_INPUT2 = WASM_BUFFER.subarray(
  WASM_PUBLIC_KEY_INPUT_PTR2,
  WASM_PUBLIC_KEY_INPUT_PTR2 + validate.PUBLIC_KEY_UNCOMPRESSED_SIZE
);
const X_ONLY_PUBLIC_KEY_INPUT = WASM_BUFFER.subarray(
  WASM_X_ONLY_PUBLIC_KEY_INPUT_PTR,
  WASM_X_ONLY_PUBLIC_KEY_INPUT_PTR + validate.X_ONLY_PUBLIC_KEY_SIZE
);
const X_ONLY_PUBLIC_KEY_INPUT2 = WASM_BUFFER.subarray(
  WASM_X_ONLY_PUBLIC_KEY_INPUT2_PTR,
  WASM_X_ONLY_PUBLIC_KEY_INPUT2_PTR + validate.X_ONLY_PUBLIC_KEY_SIZE
);
const TWEAK_INPUT = WASM_BUFFER.subarray(
  WASM_TWEAK_INPUT_PTR,
  WASM_TWEAK_INPUT_PTR + validate.TWEAK_SIZE
);
const HASH_INPUT = WASM_BUFFER.subarray(
  WASM_HASH_INPUT_PTR,
  WASM_HASH_INPUT_PTR + validate.HASH_SIZE
);
const EXTRA_DATA_INPUT = WASM_BUFFER.subarray(
  WASM_EXTRA_DATA_INPUT_PTR,
  WASM_EXTRA_DATA_INPUT_PTR + validate.EXTRA_DATA_SIZE
);
const SIGNATURE_INPUT = WASM_BUFFER.subarray(
  WASM_SIGNATURE_INPUT_PTR,
  WASM_SIGNATURE_INPUT_PTR + validate.SIGNATURE_SIZE
);

// veil
const KI_OUTPUT = WASM_BUFFER.subarray(
  WASM_KI_OUTPUT_PTR,
  WASM_KI_OUTPUT_PTR + validate.PUBLIC_KEY_COMPRESSED_SIZE
);

const PK_INPUT = WASM_BUFFER.subarray(
  WASM_PK_INPUT_PTR,
  WASM_PK_INPUT_PTR + validate.PUBLIC_KEY_COMPRESSED_SIZE
);

const SK_INPUT = WASM_BUFFER.subarray(
  WASM_SK_INPUT_PTR,
  WASM_SK_INPUT_PTR + validate.PUBLIC_KEY_COMPRESSED_SIZE
);

// rangeproof
const BLIND_OUTPUT = WASM_BUFFER.subarray(
  WASM_BLIND_OUTPUT_PTR,
  WASM_BLIND_OUTPUT_PTR + 32
);

const MESSAGE_OUTPUT = WASM_BUFFER.subarray(
  WASM_MESSAGE_OUTPUT_PTR,
  WASM_MESSAGE_OUTPUT_PTR + 256
);

const NONCE_OUTPUT = WASM_BUFFER.subarray(
  WASM_NONCE_OUTPUT_PTR,
  WASM_NONCE_OUTPUT_PTR + 32
);

const COMMIT = WASM_BUFFER.subarray(
  WASM_COMMIT_PTR,
  WASM_COMMIT_PTR + 33
);

const PROOF = WASM_BUFFER.subarray(
  WASM_PROOF_PTR,
  WASM_PROOF_PTR + 40960
);

const PROOFRESULT = WASM_BUFFER.subarray(
  WASM_PROOFRESULT_PTR,
  WASM_PROOFRESULT_PTR + 40
);


// new buffers

// BLINDS - big array
const BLINDS = WASM_BUFFER.subarray(
  WASM_BLINDS_PTR,
  WASM_BLINDS_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// M_INPUT - big array
const M_INPUT = WASM_BUFFER.subarray(
  WASM_M_INPUT_PTR,
  WASM_M_INPUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// PCM_IN - big array
const PCM_IN = WASM_BUFFER.subarray(
  WASM_PCM_IN_PTR,
  WASM_PCM_IN_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// PCM_OUT - big array
const PCM_OUT = WASM_BUFFER.subarray(
  WASM_PCM_OUT_PTR,
  WASM_PCM_OUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// KI_BIG_OUTPUT - big array
const KI_BIG_OUTPUT = WASM_BUFFER.subarray(
  WASM_KI_BIG_OUTPUT_PTR,
  WASM_KI_BIG_OUTPUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// PC_OUTPUT - big array
const PC_OUTPUT = WASM_BUFFER.subarray(
  WASM_PC_OUTPUT_PTR,
  WASM_PC_OUTPUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// PS_OUTPUT - big array
const PS_OUTPUT = WASM_BUFFER.subarray(
  WASM_PS_OUTPUT_PTR,
  WASM_PS_OUTPUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// PREIMAGE_INPUT - 32 bytes,
const PREIMAGE_INPUT = WASM_BUFFER.subarray(
  WASM_PREIMAGE_INPUT_PTR,
  WASM_PREIMAGE_INPUT_PTR + 32
);
// SKS_INPUT - big array
const SKS_INPUT = WASM_BUFFER.subarray(
  WASM_SKS_INPUT_PTR,
  WASM_SKS_INPUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);
// PKS_INPUT - big array
const PKS_INPUT = WASM_BUFFER.subarray(
  WASM_PKS_INPUT_PTR,
  WASM_PKS_INPUT_PTR + validate.WTF_MERGED_ARRAY_SIZE
);

// end

// end

function assumeCompression(compressed?: boolean, p?: Uint8Array): number {
  if (compressed === undefined) {
    return p !== undefined ? p.length : validate.PUBLIC_KEY_COMPRESSED_SIZE;
  }
  return compressed
    ? validate.PUBLIC_KEY_COMPRESSED_SIZE
    : validate.PUBLIC_KEY_UNCOMPRESSED_SIZE;
}

function _isPoint(p: Uint8Array): boolean {
  try {
    PUBLIC_KEY_INPUT.set(p);
    return wasm.isPoint(p.length) === 1;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
  }
}

export function __initializeContext(): void {
  wasm.initializeContext();
}

export function isPoint(p: Uint8Array): boolean {
  return validate.isDERPoint(p) && _isPoint(p);
}

export function isPointCompressed(p: Uint8Array): boolean {
  return validate.isPointCompressed(p) && _isPoint(p);
}

export function isXOnlyPoint(p: Uint8Array): boolean {
  return validate.isXOnlyPoint(p) && _isPoint(p);
}

export function isPrivate(d: Uint8Array): boolean {
  return validate.isPrivate(d);
}

export function pointAdd(
  pA: Uint8Array,
  pB: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(pA);
  validate.validatePoint(pB);
  const outputlen = assumeCompression(compressed, pA);
  try {
    PUBLIC_KEY_INPUT.set(pA);
    PUBLIC_KEY_INPUT2.set(pB);
    return wasm.pointAdd(pA.length, pB.length, outputlen) === 1
      ? PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
    PUBLIC_KEY_INPUT2.fill(0);
  }
}

export function pointAddScalar(
  p: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(p);
  validate.validateTweak(tweak);
  const outputlen = assumeCompression(compressed, p);
  try {
    PUBLIC_KEY_INPUT.set(p);
    TWEAK_INPUT.set(tweak);
    return wasm.pointAddScalar(p.length, outputlen) === 1
      ? PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export function pkTweakAddRaw(
  p: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  try {
    PUBLIC_KEY_INPUT.set(p);
    TWEAK_INPUT.set(tweak);
    return wasm.pkTweakAddRaw() === 1
      ? PUBLIC_KEY_INPUT.slice(0)
      : null;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export function pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array {
  validate.validatePoint(p);
  const outputlen = assumeCompression(compressed, p);
  try {
    PUBLIC_KEY_INPUT.set(p);
    wasm.pointCompress(p.length, outputlen);
    return PUBLIC_KEY_INPUT.slice(0, outputlen);
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
  }
}

export function pointFromScalar(
  d: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePrivate(d);
  const outputlen = assumeCompression(compressed);
  try {
    PRIVATE_KEY_INPUT.set(d);
    return wasm.pointFromScalar(outputlen) === 1
      ? PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    PRIVATE_KEY_INPUT.fill(0);
    PUBLIC_KEY_INPUT.fill(0);
  }
}

export function xOnlyPointFromScalar(d: Uint8Array): Uint8Array {
  validate.validatePrivate(d);
  try {
    PRIVATE_KEY_INPUT.set(d);
    wasm.xOnlyPointFromScalar();
    return X_ONLY_PUBLIC_KEY_INPUT.slice(0, validate.X_ONLY_PUBLIC_KEY_SIZE);
  } finally {
    PRIVATE_KEY_INPUT.fill(0);
    X_ONLY_PUBLIC_KEY_INPUT.fill(0);
  }
}

export function xOnlyPointFromPoint(p: Uint8Array): Uint8Array {
  validate.validatePoint(p);
  try {
    PUBLIC_KEY_INPUT.set(p);
    wasm.xOnlyPointFromPoint(p.length);
    return X_ONLY_PUBLIC_KEY_INPUT.slice(0, validate.X_ONLY_PUBLIC_KEY_SIZE);
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
    X_ONLY_PUBLIC_KEY_INPUT.fill(0);
  }
}

export function pointMultiply(
  p: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(p);
  validate.validateTweak(tweak);
  const outputlen = assumeCompression(compressed, p);
  try {
    PUBLIC_KEY_INPUT.set(p);
    TWEAK_INPUT.set(tweak);
    return wasm.pointMultiply(p.length, outputlen) === 1
      ? PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export function privateAdd(
  d: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  validate.validatePrivate(d);
  validate.validateTweak(tweak);
  try {
    PRIVATE_KEY_INPUT.set(d);
    TWEAK_INPUT.set(tweak);
    return wasm.privateAdd() === 1
      ? PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
      : null;
  } finally {
    PRIVATE_KEY_INPUT.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export function privateSub(
  d: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  validate.validatePrivate(d);
  validate.validateTweak(tweak);

  // We can not pass zero tweak to WASM, because WASM use `secp256k1_ec_seckey_negate` for tweak negate.
  // (zero is not valid seckey)
  if (validate.isZero(tweak)) {
    return new Uint8Array(d);
  }

  try {
    PRIVATE_KEY_INPUT.set(d);
    TWEAK_INPUT.set(tweak);
    return wasm.privateSub() === 1
      ? PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
      : null;
  } finally {
    PRIVATE_KEY_INPUT.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export function privateNegate(d: Uint8Array): Uint8Array {
  validate.validatePrivate(d);

  try {
    PRIVATE_KEY_INPUT.set(d);
    wasm.privateNegate();
    return PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE);
  } finally {
    PRIVATE_KEY_INPUT.fill(0);
  }
}

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}
export function xOnlyPointAddTweak(
  p: Uint8Array,
  tweak: Uint8Array
): XOnlyPointAddTweakResult | null {
  validate.validateXOnlyPoint(p);
  validate.validateTweak(tweak);
  try {
    X_ONLY_PUBLIC_KEY_INPUT.set(p);
    TWEAK_INPUT.set(tweak);
    const parity = wasm.xOnlyPointAddTweak();
    return parity !== -1
      ? {
        parity,
        xOnlyPubkey: X_ONLY_PUBLIC_KEY_INPUT.slice(
          0,
          validate.X_ONLY_PUBLIC_KEY_SIZE
        ),
      }
      : null;
  } finally {
    X_ONLY_PUBLIC_KEY_INPUT.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export type TweakParity = 1 | 0;
export function xOnlyPointAddTweakCheck(
  point: Uint8Array,
  tweak: Uint8Array,
  resultToCheck: Uint8Array,
  tweakParity?: TweakParity
): boolean {
  validate.validateXOnlyPoint(point);
  validate.validateXOnlyPoint(resultToCheck);
  validate.validateTweak(tweak);
  const hasParity = tweakParity !== undefined;
  if (hasParity) validate.validateParity(tweakParity);
  try {
    X_ONLY_PUBLIC_KEY_INPUT.set(point);
    X_ONLY_PUBLIC_KEY_INPUT2.set(resultToCheck);
    TWEAK_INPUT.set(tweak);
    if (hasParity) {
      return wasm.xOnlyPointAddTweakCheck(tweakParity) === 1;
    } else {
      wasm.xOnlyPointAddTweak();
      const newKey = X_ONLY_PUBLIC_KEY_INPUT.slice(
        0,
        validate.X_ONLY_PUBLIC_KEY_SIZE
      );
      return compare(newKey, resultToCheck) === 0;
    }
  } finally {
    X_ONLY_PUBLIC_KEY_INPUT.fill(0);
    X_ONLY_PUBLIC_KEY_INPUT2.fill(0);
    TWEAK_INPUT.fill(0);
  }
}

export function sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);
  try {
    HASH_INPUT.set(h);
    PRIVATE_KEY_INPUT.set(d);
    if (e !== undefined) EXTRA_DATA_INPUT.set(e);
    wasm.sign(e === undefined ? 0 : 1);
    return SIGNATURE_INPUT.slice(0, validate.SIGNATURE_SIZE);
  } finally {
    HASH_INPUT.fill(0);
    PRIVATE_KEY_INPUT.fill(0);
    if (e !== undefined) EXTRA_DATA_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
  }
}

export interface RecoverableSignature {
  signature: Uint8Array;
  recoveryId: RecoveryIdType;
}
export function signRecoverable(
  h: Uint8Array,
  d: Uint8Array,
  e?: Uint8Array
): RecoverableSignature {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);
  try {
    HASH_INPUT.set(h);
    PRIVATE_KEY_INPUT.set(d);
    if (e !== undefined) EXTRA_DATA_INPUT.set(e);
    const recoveryId: RecoveryIdType = wasm.signRecoverable(
      e === undefined ? 0 : 1
    );
    const signature: Uint8Array = SIGNATURE_INPUT.slice(
      0,
      validate.SIGNATURE_SIZE
    );
    return {
      signature,
      recoveryId,
    };
  } finally {
    HASH_INPUT.fill(0);
    PRIVATE_KEY_INPUT.fill(0);
    if (e !== undefined) EXTRA_DATA_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
  }
}

export function signSchnorr(
  h: Uint8Array,
  d: Uint8Array,
  e?: Uint8Array
): Uint8Array {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);
  try {
    HASH_INPUT.set(h);
    PRIVATE_KEY_INPUT.set(d);
    if (e !== undefined) EXTRA_DATA_INPUT.set(e);
    wasm.signSchnorr(e === undefined ? 0 : 1);
    return SIGNATURE_INPUT.slice(0, validate.SIGNATURE_SIZE);
  } finally {
    HASH_INPUT.fill(0);
    PRIVATE_KEY_INPUT.fill(0);
    if (e !== undefined) EXTRA_DATA_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
  }
}

export function verify(
  h: Uint8Array,
  Q: Uint8Array,
  signature: Uint8Array,
  strict = false
): boolean {
  validate.validateHash(h);
  validate.validatePoint(Q);
  validate.validateSignature(signature);
  try {
    HASH_INPUT.set(h);
    PUBLIC_KEY_INPUT.set(Q);
    SIGNATURE_INPUT.set(signature);
    return wasm.verify(Q.length, strict === true ? 1 : 0) === 1 ? true : false;
  } finally {
    HASH_INPUT.fill(0);
    PUBLIC_KEY_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
  }
}

export type RecoveryIdType = 0 | 1 | 2 | 3;
export function recover(
  h: Uint8Array,
  signature: Uint8Array,
  recoveryId: RecoveryIdType,
  compressed = false
): Uint8Array | null {
  validate.validateHash(h);
  validate.validateSignature(signature);
  validate.validateSignatureNonzeroRS(signature);
  if (recoveryId & 2) {
    validate.validateSigrPMinusN(signature);
  }
  validate.validateSignatureCustom((): boolean =>
    isXOnlyPoint(signature.subarray(0, 32))
  );

  const outputlen = assumeCompression(compressed);
  try {
    HASH_INPUT.set(h);
    SIGNATURE_INPUT.set(signature);

    return wasm.recover(outputlen, recoveryId) === 1
      ? PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    HASH_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
    PUBLIC_KEY_INPUT.fill(0);
  }
}

export function verifySchnorr(
  h: Uint8Array,
  Q: Uint8Array,
  signature: Uint8Array
): boolean {
  validate.validateHash(h);
  validate.validateXOnlyPoint(Q);
  validate.validateSignature(signature);
  try {
    HASH_INPUT.set(h);
    X_ONLY_PUBLIC_KEY_INPUT.set(Q);
    SIGNATURE_INPUT.set(signature);
    return wasm.verifySchnorr() === 1 ? true : false;
  } finally {
    HASH_INPUT.fill(0);
    X_ONLY_PUBLIC_KEY_INPUT.fill(0);
    SIGNATURE_INPUT.fill(0);
  }
}

// veil
export function getKeyImage(
  pk: Uint8Array,
  sk: Uint8Array
): Uint8Array | null {
  const outputlen = pk.length;
  const inputlen = pk.length;
  const inputlensk = sk.length;
  try {
    PK_INPUT.set(pk);
    SK_INPUT.set(sk);
    const res = wasm.getKeyImage(outputlen, inputlen, inputlensk);
    return (res == 0 || res == 3) ? KI_OUTPUT.slice(0, validate.PUBLIC_KEY_COMPRESSED_SIZE) : null;
  } finally {
    KI_OUTPUT.fill(0);
    PK_INPUT.fill(0);
    SK_INPUT.fill(0);
  }
}

/*
            BLIND_OUT.as_mut_ptr(),
            &mut value_out,
            MESSAGE_OUT.as_mut_ptr(),
            &mut outlen,
            NONCE.as_mut_ptr(),
            &mut min_value,
            &mut max_value,
            COMMIT.as_mut_ptr(),
            PROOF.as_mut_ptr(),
            plen,
            BLIND_OUT.as_mut_ptr(),
*/
export interface RangeProofRewindResult {
  blindOut: Uint8Array,
  messageOut: Uint8Array,
  value: bigint,
  minValue: bigint,
  maxValue: bigint
}

export function rangeProofRewind(
  nonce: Uint8Array,
  commitment: Uint8Array,
  rangeproof: Uint8Array,
): RangeProofRewindResult | null {
  try {
    const out_len = 256;
    NONCE_OUTPUT.set(nonce);
    MESSAGE_OUTPUT.fill(0);
    COMMIT.set(commitment);
    PROOF.set(rangeproof);
    const proofLen = rangeproof.length;

    const res = wasm.rangeProofRewind(out_len, proofLen);
    //console.log(PROOFRESULT.slice(0, 40));
    const dv = new DataView(PROOFRESULT.slice(0, 40).buffer);
    return res == 1 ? {
      blindOut: BLIND_OUTPUT.slice(0, 32),
      value: dv.getBigUint64(0, true),
      minValue: dv.getBigUint64(16, true),
      maxValue: dv.getBigUint64(24, true),
      messageOut: MESSAGE_OUTPUT.slice(0, parseInt(dv.getBigUint64(32, true).toString()))
    } : null;
  } finally {
    PROOFRESULT.fill(0);
    BLIND_OUTPUT.fill(0);
    MESSAGE_OUTPUT.fill(0);
    NONCE_OUTPUT.fill(0);
    COMMIT.fill(0);
    PROOF.fill(0);
  }
}

export function rangeProofVerify(
  commitment: Uint8Array,
  rangeproof: Uint8Array,
): number {
  try {
    const out_len = 256;
    MESSAGE_OUTPUT.fill(0);
    COMMIT.set(commitment);
    PROOF.set(rangeproof);
    const proofLen = rangeproof.length;

    const res = wasm.rangeProofVerify(out_len, proofLen);
    return res;
  } finally {
    PROOFRESULT.fill(0);
    BLIND_OUTPUT.fill(0);
    MESSAGE_OUTPUT.fill(0);
    NONCE_OUTPUT.fill(0);
    COMMIT.fill(0);
    PROOF.fill(0);
  }
}

export function ECDH_VEIL(publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array | null {
  try {
    PUBLIC_KEY_INPUT.set(publicKey);
    PRIVATE_KEY_INPUT.set(privateKey);
    const res = wasm.ECDH_VEIL(publicKey.length);
    return res == 0 ? NONCE_OUTPUT.slice(0, 32) : NONCE_OUTPUT.slice(0, 32); // TO-DO validation, return null if error
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
    PRIVATE_KEY_INPUT.fill(0);
    NONCE_OUTPUT.fill(0);

  }
}

export interface PedersenCommitResult {
  blind: Uint8Array,
  commitment: Uint8Array
}

export function pedersenCommit(
  commitment: Uint8Array,
  blind_output: Uint8Array,
  value: bigint
): PedersenCommitResult | null {
  try {
    BLIND_OUTPUT.set(blind_output);
    COMMIT.set(commitment);

    const res = wasm.pedersenCommit(value);

    if (res == 1) {
      const out: PedersenCommitResult = {
        blind: BLIND_OUTPUT.slice(0, 32),
        commitment: COMMIT.slice(0, 33)
      };
      return out;
    } else return null;
  } finally {
    BLIND_OUTPUT.fill(0);
    COMMIT.fill(0);
  }
}

export interface RangeProofSignResult {
  proof: Uint8Array,
  proof_len: number,
  commit: Uint8Array,
  blind_output: Uint8Array,
  nonce_output: Uint8Array,
  message_output: Uint8Array
}

export function rangeproofSign(
  proof: Uint8Array,
  plen: number,
  min_value: bigint,
  commitment: Uint8Array,
  blind: Uint8Array,
  nonce: Uint8Array,
  exp: number,
  min_bits: number,
  value: bigint,
  message: Uint8Array,
  msg_len: number
): RangeProofSignResult | null {
  try {
    PROOF.set(proof);
    COMMIT.set(commitment);
    BLIND_OUTPUT.set(blind);
    NONCE_OUTPUT.set(nonce);
    MESSAGE_OUTPUT.set(message);

    const res = wasm.rangeproofSign(plen, min_value, exp, min_bits, value, msg_len);

    if (res == 1) {
      const dv = new DataView(PRIVATE_KEY_INPUT.slice(0, 4).buffer);
      const nplen = Number(dv.getUint32(0, true));
      const out: RangeProofSignResult = {
        proof: PROOF.slice(0, nplen),
        proof_len: nplen,
        commit: COMMIT.slice(0, 33),
        blind_output: BLIND_OUTPUT.slice(0, 32),
        nonce_output: NONCE_OUTPUT.slice(0, 32),
        message_output: MESSAGE_OUTPUT.slice(0, msg_len)
      };
      return out;
    } else return null;
  } finally {
    PROOF.fill(0);
    COMMIT.fill(0);
    BLIND_OUTPUT.fill(0);
    NONCE_OUTPUT.fill(0);
    MESSAGE_OUTPUT.fill(0);
  }
}




//
//
//   NEW METHODS
//
//
export function pedersenBlindSum(
  blind: Uint8Array,
  blinds: Array<Uint8Array>,
  n: number,
  npositive: number
): Uint8Array | null {
  try {
    BLIND_OUTPUT.set(blind); // return!
    BLINDS.fill(0);

    let index = 0;
    for (const blind_local of blinds) {
      BLINDS.set(blind_local, index);
      index += blind_local.length; //32?
    }

    //blinds_size = n?
    const res = wasm.pedersenBlindSum(n, n, npositive);

    if (res > 0) {
      return BLIND_OUTPUT.slice(0, 32);
    } else return null;
  } finally {
    BLIND_OUTPUT.fill(0);
    BLINDS.fill(0);
  }
}

export interface PrepareMlsagResult {
  M: Uint8Array,
  SK: Uint8Array
}

export function prepareMlsag(
  m_input: Uint8Array,
  sk_input: Uint8Array,
  nOuts: number, nBlinded: number, vpInCommitsLen: number, vpBlindsLen: number, nCols: number, nRows: number,
  vpInCommits: Array<Uint8Array>,
  vpOutCommits: Array<Uint8Array>,
  vpBlinds: Array<Uint8Array>
): PrepareMlsagResult | null {
  try {
    M_INPUT.set(m_input); // return!
    SK_INPUT.set(sk_input); // return!

    PCM_IN.fill(0);
    let index = 0;
    for (const local of vpInCommits) {
      PCM_IN.set(local, index);
      index += local.length;
    }

    PCM_OUT.fill(0);
    index = 0;
    for (const local of vpOutCommits) {
      PCM_OUT.set(local, index);
      index += local.length;
    }

    BLINDS.fill(0);
    index = 0;
    for (const local of vpBlinds) {
      BLINDS.set(local, index);
      index += local.length;
    }

    //blinds_size = n?
    const res = wasm.prepareMlsag(nOuts, nBlinded, vpInCommitsLen, vpBlindsLen, nCols, nRows);

    if (res == 0) {
      return {
        M: M_INPUT.slice(0, m_input.length),
        SK: SK_INPUT.slice(0, sk_input.length)
      };
    } else return null;
  } finally {
    M_INPUT.fill(0);
    SK_INPUT.fill(0);
    PCM_IN.fill(0);
    PCM_OUT.fill(0);
    BLINDS.fill(0);
  }
}



export interface GenerateMlsagResult {
  KI: Uint8Array,
  PC: Uint8Array,
  PS: Uint8Array
}

export function generateMlsag(
  ki: Uint8Array,
  pc: Uint8Array,
  ps: Uint8Array,
  nonce: Uint8Array,
  preimage: Uint8Array,
  nCols: number, nRows: number, indexRef: number, sk_size: number,
  sks: Array<Uint8Array>,
  pk: Uint8Array
): GenerateMlsagResult | null {
  try {
    KI_BIG_OUTPUT.set(ki); // return!
    PC_OUTPUT.set(pc); // return!
    PS_OUTPUT.set(ps); // return!
    NONCE_OUTPUT.set(nonce);
    PREIMAGE_INPUT.set(preimage);
    PKS_INPUT.set(pk);

    SKS_INPUT.fill(0);
    let index = 0;
    for (const local of sks) {
      SKS_INPUT.set(local, index);
      index += local.length;
    }

    //blinds_size = n?
    const res = wasm.generateMlsag(nCols, nRows, indexRef, sk_size);
    if (res == 0) {
      return {
        KI: KI_BIG_OUTPUT.slice(0, ki.length),
        PC: PC_OUTPUT.slice(0, pc.length),
        PS: PS_OUTPUT.slice(0, ps.length)
      };
    } else return null;
  } finally {
    KI_BIG_OUTPUT.fill(0);
    PC_OUTPUT.fill(0);
    PS_OUTPUT.fill(0);
    NONCE_OUTPUT.fill(0);
    PREIMAGE_INPUT.fill(0);
    PKS_INPUT.fill(0);
    SKS_INPUT.fill(0);
  }
}


export function verifyMlsag(
  preimage: Uint8Array,
  nCols: number, nRows: number,
  pk: Uint8Array,
  ki: Uint8Array,
  pc: Uint8Array,
  ps: Uint8Array
): number {
  try {
    PREIMAGE_INPUT.set(preimage);
    PKS_INPUT.set(pk);
    KI_BIG_OUTPUT.set(ki);
    PC_OUTPUT.set(pc);
    PS_OUTPUT.set(ps);

    const res = wasm.verifyMlsag(nCols, nRows);
    return res;
  } finally {
    PREIMAGE_INPUT.fill(0);
    PKS_INPUT.fill(0);
    KI_BIG_OUTPUT.fill(0);
    PC_OUTPUT.fill(0);
    PS_OUTPUT.fill(0);
  }
}

export function seckeyVerify(
  input: Uint8Array
): boolean {
  try {
    PUBLIC_KEY_INPUT.set(input);

    const res = wasm.seckeyVerify();
    return res == 1;
  } finally {
    PUBLIC_KEY_INPUT.fill(0);
  }
}