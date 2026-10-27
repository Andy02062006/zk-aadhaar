import test from "node:test";
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { parseSecureQr } from "../src/aadhaar.ts";
import { buildCircuitInputs, bytesToBig, expectedNullifier, hashToRsaChunks, toChunks, appIdToField, shaPad } from "../src/inputs.ts";
import { fakeQr, makeKey } from "../src/testing.ts";

const { privateKey, publicKey } = makeKey();
const modulus = bytesToBig(Buffer.from(publicKey.export({ format: "jwk" }).n!, "base64url"));
const person = { name: "ASHA KRISHNAN", dob: "07-03-1998", gender: "F", pincode: "600042", last4: "4821", ts: "20261019101010123" };
const ch = { appId: appIdToField("test-app").toString(), nonce: "12345", minAge: 18, currentDate: 20261019, revealGender: 1 as const, revealPincode: 0 as const };

test("parses QR and locates fields", () => {
  const qr = parseSecureQr(fakeQr(privateKey, person));
  assert.deepEqual(qr.text, { name: person.name, dob: person.dob, gender: "F", pincode: "600042", last4: "4821" });
  assert.equal(qr.signature.length, 256);
});

test("circuit inputs mirror the circuit's constraints", async () => {
  const qr = parseSecureQr(fakeQr(privateKey, person));
  const inp = await buildCircuitInputs(qr, modulus, ch);
  const d = inp.data as number[];

  assert.equal(inp.dataLenPadded % 64, 0);
  // SHA padding: 0x80 right after the message, bit-length in last 8 bytes
  assert.equal(d[qr.signedData.length], 0x80);
  // fields start right after a delimiter and the field counter matches the expected index
  const countBefore = (i: number) => d.slice(0, i).filter((b) => b === 255).length;
  for (const [s, idx] of [[inp.refStart, 2], [inp.nameStart, 3], [inp.dobStart, 4], [inp.genderStart, 5], [inp.pincodeStart, 11]] as const) {
    assert.equal(d[s - 1], 255); assert.equal(countBefore(s), idx);
  }
  assert.equal(d[inp.dobStart + 10], 255);
  assert.equal(d[inp.pincodeStart + 6], 255);

  // RSA: sig^65537 mod n == PKCS#1 v1.5 EM, and the low 256 bits of EM equal the circuit's hash chunks
  const hash = createHash("sha256").update(qr.signedData).digest();
  let r = 1n, b = bytesToBig(qr.signature) % modulus;
  for (let e = 65537n; e > 0n; e >>= 1n) { if (e & 1n) r = (r * b) % modulus; b = (b * b) % modulus; }
  const prefix = Buffer.from("3031300d060960864801650304020105000420", "hex");
  const expected = Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(256 - 3 - prefix.length - 32, 0xff), Buffer.from([0]), prefix, hash]);
  assert.equal(r, bytesToBig(expected));
  const emChunks = toChunks(r), hc = hashToRsaChunks(hash);
  assert.deepEqual(emChunks.slice(0, 2), hc.slice(0, 2));
  assert.equal(emChunks[2] & ((1n << 14n) - 1n), hc[2]); // top 14 hash bits live in chunk 2
});

test("nullifier is stable across QR re-downloads and differs per app / person", async () => {
  const a = parseSecureQr(fakeQr(privateKey, person));
  const b = parseSecureQr(fakeQr(privateKey, { ...person, ts: "20270101000000999" }));
  const app1 = appIdToField("app-1"), app2 = appIdToField("app-2");
  assert.equal(await expectedNullifier(app1, a), await expectedNullifier(app1, b));
  assert.notEqual(await expectedNullifier(app1, a), await expectedNullifier(app2, a));
  const other = parseSecureQr(fakeQr(privateKey, { ...person, name: "RAVI KUMAR" }));
  assert.notEqual(await expectedNullifier(app1, a), await expectedNullifier(app1, other));
});

test("oversized payload is rejected instead of silently truncated", () => {
  assert.throws(() => shaPad(Buffer.alloc(1600)), /circuit supports/);
});
