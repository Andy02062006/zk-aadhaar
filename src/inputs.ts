import { createHash, X509Certificate } from "node:crypto";
import { buildPoseidon } from "circomlibjs";
import { F, type ParsedQr } from "./aadhaar.ts";

export const MAX_BYTES = 1152;  // must match AadhaarAuth(1536) in the circuit
export const CHUNK_BITS = 121n;
export const K = 17;

export interface Challenge {
  appId: string; nonce: string; minAge: number; currentDate: number;
  revealGender: 0 | 1; revealPincode: 0 | 1;
}

export const bytesToBig = (b: Uint8Array) => BigInt("0x" + Buffer.from(b).toString("hex"));

export function toChunks(x: bigint): bigint[] {
  const mask = (1n << CHUNK_BITS) - 1n;
  return Array.from({ length: K }, (_, i) => (x >> (CHUNK_BITS * BigInt(i))) & mask);
}

/** Same chunking the circuit applies to the SHA-256 output (little-endian 121-bit limbs). */
export function hashToRsaChunks(hash: Buffer): bigint[] {
  return toChunks(bytesToBig(hash));
}

export function shaPad(msg: Uint8Array, max = MAX_BYTES) {
  const total = Math.ceil((msg.length + 9) / 64) * 64;
  if (total > max) throw new Error(`Signed payload needs ${total} bytes after padding; circuit supports ${max}`);
  const buf = Buffer.alloc(max);
  Buffer.from(msg).copy(buf);
  buf[msg.length] = 0x80;
  buf.writeBigUInt64BE(BigInt(msg.length) * 8n, total - 8);
  return { padded: Array.from(buf), len: total };
}

/** Extract the RSA modulus from UIDAI's X.509 certificate (PEM). */
export function modulusFromCert(pem: string): bigint {
  const jwk = new X509Certificate(pem).publicKey.export({ format: "jwk" });
  return bytesToBig(Buffer.from(jwk.n!, "base64url"));
}

let poseidonP: Promise<any> | undefined;
export async function poseidon(inputs: (bigint | number)[]): Promise<bigint> {
  poseidonP ??= buildPoseidon();
  const p = await poseidonP;
  return BigInt(p.F.toString(p(inputs)));
}

export async function pubkeyHash(modulus: bigint): Promise<bigint> {
  const c = toChunks(modulus);
  return poseidon([await poseidon(c.slice(0, 9)), await poseidon(c.slice(9))]);
}

/** Server-side: map an application name to a field element. */
export const appIdToField = (name: string) =>
  BigInt("0x" + createHash("sha256").update(name).digest("hex")) >> 8n;

export async function buildCircuitInputs(qr: ParsedQr, modulus: bigint, ch: Challenge) {
  const { padded, len } = shaPad(qr.signedData);
  const s = qr.starts;
  return {
    pubkeyHash: (await pubkeyHash(modulus)).toString(),
    appId: ch.appId, nonce: ch.nonce, minAge: ch.minAge, currentDate: ch.currentDate,
    revealGender: ch.revealGender, revealPincode: ch.revealPincode,
    data: padded, dataLenPadded: len,
    signature: toChunks(bytesToBig(qr.signature)).map(String),
    modulus: toChunks(modulus).map(String),
    refStart: s[F.REF], nameStart: s[F.NAME], dobStart: s[F.DOB],
    genderStart: s[F.GENDER], pincodeStart: s[F.PINCODE],
  };
}

/** TS mirror of the circuit's nullifier (used by tests). */
export async function expectedNullifier(appId: bigint, qr: ParsedQr) {
  const t = qr.text;
  const pack = (b: Buffer) => b.reduce((a, v, i) => a + BigInt(v) * 256n ** BigInt(i), 0n);
  const dec = (s: string) => [...s].reduce((a, c, i) => a + BigInt(c) * 10n ** BigInt(i), 0n);
  const name = Buffer.from(t.name, "utf8").subarray(0, 16);
  return poseidon([appId, dec(t.last4), pack(Buffer.from(t.dob)), BigInt(t.gender.charCodeAt(0)), dec(t.pincode), pack(name)]);
}
