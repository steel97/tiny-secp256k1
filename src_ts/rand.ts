//import { randomBytes } from "crypto";
import * as randomBytes from "randombytes";

export function generateInt32(): number {
  return randomBytes.default(4).readInt32BE(0);
  //return randomBytes(4).readInt32BE(0);
}

export function printn(x: number): void {
  console.log(x);
}