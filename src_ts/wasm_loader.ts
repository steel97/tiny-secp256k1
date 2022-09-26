import { readFileSync } from "fs";
import { path } from "./wasm_path.js"; //import { path } from "./wasm_path_cjs.js";
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

  // new buffers

  // BLINDS - big array
  BLINDS: WebAssemblyGlobal;
  // M_INPUT - big array
  M_INPUT: WebAssemblyGlobal;
  // PCM_IN - big array
  PCM_IN: WebAssemblyGlobal;
  // PCM_OUT - big array
  PCM_OUT: WebAssemblyGlobal;
  // KI_OUTPUT - big array
  KI_BIG_OUTPUT: WebAssemblyGlobal; //!!!
  // PC_OUTPUT - big array
  PC_OUTPUT: WebAssemblyGlobal;
  // PS_OUTPUT - big array
  PS_OUTPUT: WebAssemblyGlobal;
  // PREIMAGE_INPUT - 32 bytes,
  PREIMAGE_INPUT: WebAssemblyGlobal;
  // SKS_INPUT - big array
  SKS_INPUT: WebAssemblyGlobal;
  // PKS_INPUT - big array
  PKS_INPUT: WebAssemblyGlobal;

  // end

  // end

  initializeContext: () => void;
  isPoint: (p: number) => number;
  pointAdd: (pA: number, pB: number, outputlen: number) => number;
  pointAddScalar: (p: number, outputlen: number) => number;
  pkTweakAddRaw: () => number;
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
  rangeProofRewind: (outlen: number, plen: number) => number;
  rangeProofVerify: (outlen: number, plen: number) => number;
  ECDH_VEIL: (inputlen: number) => number;
  pedersenCommit: (value: bigint) => number;
  rangeproofSign: (plen: number, min_value: bigint, exp: number, min_bits: number, value: bigint, msg_len: number) => number;

  pedersenBlindSum: (blinds_size: number, n: number, npositive: number) => number;
  prepareMlsag: (nOuts: number, nBlinded: number, vpInCommitsLen: number, vpBlindsLen: number, nCols: number, nRows: number) => number;
  generateMlsag: (nCols: number, nRows: number, index: number, sk_size: number) => number;
  verifyMlsag: (nCols: number, nRows: number) => number;
  seckeyVerify: () => number;
}

export default instance.exports as unknown as Secp256k1WASM;
