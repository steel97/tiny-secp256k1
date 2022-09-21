import { readFileSync } from "fs";
import { path } from "./wasm_path.js";
import * as rand from "./rand.js";
import * as validate_error from "./validate_error.js";

const binary = readFileSync(path("secp256k1.wasm"));
const imports = {
  "./rand.js": rand,
  "./validate_error.js": validate_error,
  env: {
    printf: (msg: any) => console.log(msg),
  }
};

const mod = new WebAssembly.Module(binary);
const instance = new WebAssembly.Instance(mod, imports);

interface WebAssemblyMemory {
  buffer: Uint8Array;
}

interface WebAssemblyGlobal {
  value: number;
}

type RecoveryIdType = 0 | 1 | 2 | 3;

interface Secp256k1WASM {
  memory: WebAssemblyMemory;

  PRIVATE_INPUT: WebAssemblyGlobal;
  PUBLIC_KEY_INPUT: WebAssemblyGlobal;
  PUBLIC_KEY_INPUT2: WebAssemblyGlobal;
  X_ONLY_PUBLIC_KEY_INPUT: WebAssemblyGlobal;
  X_ONLY_PUBLIC_KEY_INPUT2: WebAssemblyGlobal;
  TWEAK_INPUT: WebAssemblyGlobal;
  HASH_INPUT: WebAssemblyGlobal;
  EXTRA_DATA_INPUT: WebAssemblyGlobal;
  SIGNATURE_INPUT: WebAssemblyGlobal;

  // veil
  KI_OUTPUT: WebAssemblyGlobal;
  PK_INPUT: WebAssemblyGlobal;
  SK_INPUT: WebAssemblyGlobal;

  BLIND_OUTPUT: WebAssemblyGlobal;
  MESSAGE_OUTPUT: WebAssemblyGlobal;
  NONCE_OUTPUT: WebAssemblyGlobal;
  COMMIT: WebAssemblyGlobal;
  PROOF: WebAssemblyGlobal;
  PROOFRESULT: WebAssemblyGlobal;
  // end

  initializeContext: () => void;
  isPoint: (p: number) => number;
  pointAdd: (pA: number, pB: number, outputlen: number) => number;
  pointAddScalar: (p: number, outputlen: number) => number;
  pointCompress: (p: number, outputlen: number) => number;
  pointFromScalar: (outputlen: number) => number;
  xOnlyPointFromScalar: () => number;
  xOnlyPointFromPoint: (inputLen: number) => number;
  xOnlyPointAddTweak: () => 1 | 0 | -1;
  xOnlyPointAddTweakCheck: (parity: number) => number;
  pointMultiply: (p: number, outputlen: number) => number;
  privateAdd: () => number;
  privateSub: () => number;
  privateNegate: () => void;
  sign: (e: number) => void;
  signRecoverable: (e: number) => 0 | 1 | 2 | 3;
  signSchnorr: (e: number) => void;
  verify: (Q: number, strict: number) => number;
  verifySchnorr: () => number;
  recover: (outputlen: number, recoveryId: RecoveryIdType) => number;
  // veil
  getKeyImage: (outputlen: number, inputpkLen: number, inputskLen: number) => number;
  rangeProofRewind: (value_out: number, outlen: number, min_value: number, max_value: number, plen: number) => number;
  ECDH_VEIL: (inputlen: number) => number;
}

export default instance.exports as unknown as Secp256k1WASM;
