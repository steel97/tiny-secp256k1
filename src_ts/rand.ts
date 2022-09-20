import { randomBytes } from "crypto";

export function generateInt32(): number {
  return randomBytes(4).readInt32BE(0);
}

export function printn(x: number): void {
  console.log(x);
}