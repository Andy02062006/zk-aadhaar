import { generateKeyPairSync, createSign, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";

export function makeKey() { return generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 }); }

/** Builds a Secure-QR-shaped payload signed with a *test* key (not a real Aadhaar). */
export function fakeQr(priv: ReturnType<typeof makeKey>["privateKey"], p: {
  name: string; dob: string; gender: string; pincode: string; last4: string; ts: string;
}) {
  const fields = ["V2", "3", p.last4 + p.ts, p.name, p.dob, p.gender, "C/O Test", "Chennai", "Landmark",
    "House 1", "Location", p.pincode, "PO", "Tamil Nadu", "Street", "Sub", "VTC"];
  const text = Buffer.concat(fields.map((f) => Buffer.concat([Buffer.from(f), Buffer.from([255])])));
  const photo = Buffer.concat([Buffer.from([0xff, 0x4f, 0xff, 0x51]), randomBytes(600)]); // contains 0xFF like real JP2
  const signedData = Buffer.concat([text, photo]);
  const signature = createSign("RSA-SHA256").update(signedData).sign(priv);
  const bytes = gzipSync(Buffer.concat([signedData, signature]));
  return BigInt("0x" + bytes.toString("hex")).toString(10);
}
