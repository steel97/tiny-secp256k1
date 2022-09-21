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
  WASM_MESSAGE_OUTPUT_PTR + 32
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
  value: number,
  minValue: number,
  maxValue: number
}

export function rangeProofRewind(
  nonce: Uint8Array,
  commitment: Uint8Array,
  rangeproof: Uint8Array,
): RangeProofRewindResult | null {
  try {
    let value_out = 0;
    let out_len = 0;
    NONCE_OUTPUT.set(nonce);
    let min_value = 0;
    let max_value = 0;
    COMMIT.set(commitment);
    PROOF.set(rangeproof);
    const proofLen = rangeproof.length;

    const res = wasm.rangeProofRewind(value_out, out_len, min_value, max_value, proofLen);
    //console.log(PROOFRESULT.slice(0, 40));
    const dv = new DataView(PROOFRESULT.slice(0, 40).buffer);
    return res == 1 ? {
      blindOut: BLIND_OUTPUT.slice(0, 32),
      value: parseInt(dv.getBigUint64(0, true).toString()),
      minValue: parseInt(dv.getBigUint64(16, true).toString()),
      maxValue: parseInt(dv.getBigUint64(24, true).toString()),
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