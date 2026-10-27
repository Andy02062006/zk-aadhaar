import { gunzipSync } from "node:zlib";

export const DELIM = 255;
export const SIG_BYTES = 256;
/** Field positions in the 0xFF-delimited text section of the Secure QR. */
export const F = { VERSION: 0, FLAG: 1, REF: 2, NAME: 3, DOB: 4, GENDER: 5, PINCODE: 11 } as const;

export interface ParsedQr {
  signedData: Buffer;   // everything the UIDAI signature covers
  signature: Buffer;    // 256-byte RSA signature
  starts: number[];     // start offset of text fields 0..16
  text: { name: string; dob: string; gender: string; pincode: string; last4: string };
}

export function qrNumericToBytes(qr: string): Buffer {
  let hex = BigInt(qr.trim()).toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

export function parseSecureQr(qr: string): ParsedQr {
  const raw = gunzipSync(qrNumericToBytes(qr));
  if (raw.length <= SIG_BYTES) throw new Error("QR payload too short");
  const signature = raw.subarray(raw.length - SIG_BYTES);
  const signedData = raw.subarray(0, raw.length - SIG_BYTES);

  const delims: number[] = [];
  for (let i = 0; i < signedData.length && delims.length < 17; i++) if (signedData[i] === DELIM) delims.push(i);
  if (delims.length < 17) throw new Error("Unexpected QR layout (expected 17 text fields)");
  const starts = [0, ...delims.slice(0, 16).map((d) => d + 1)];
  const field = (k: number) => signedData.subarray(starts[k], delims[k]).toString("utf8");

  return {
    signedData, signature, starts,
    text: {
      name: field(F.NAME), dob: field(F.DOB), gender: field(F.GENDER),
      pincode: field(F.PINCODE), last4: field(F.REF).slice(0, 4),
    },
  };
}
