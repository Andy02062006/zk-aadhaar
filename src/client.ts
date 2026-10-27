// usage: tsx src/client.ts <qr-numeric-file> [serverUrl]
import { readFileSync } from "node:fs";
import { parseSecureQr } from "./aadhaar.ts";
import { buildCircuitInputs, modulusFromCert } from "./inputs.ts";
import { prove } from "./prover.ts";

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

const [qrFile, server = "http://localhost:3000"] = process.argv.slice(2);
if (!qrFile) fail("usage: npm run client -- <qr-numeric-file> [serverUrl]");
const qr = parseSecureQr(readFileSync(qrFile, "utf8")); // the QR never leaves this machine
const modulus = modulusFromCert(readFileSync(process.env.UIDAI_CERT ?? "uidai_offline_publickey.cer", "utf8"));

const res = await fetch(`${server}/auth/challenge`, { method: "POST" })
  .catch(() => fail(`Can't reach the auth server at ${server}. Start it with: npm run server`));
const { challengeId, ...ch } = await res.json();

// Check the server's requirements before spending ~30 s on a proof the circuit would refuse.
// Same rule as circuit step 5: DOB + minAge years must be on or before currentDate.
const dob = /^(\d{2})-(\d{2})-(\d{4})$/.exec(qr.text.dob);
if (!dob) fail("This QR's date of birth isn't a full DD-MM-YYYY date (some Aadhaars only have the year), so the circuit can't check age.");
const [, dd, mm, yyyy] = dob.map(Number);
if ((yyyy + ch.minAge) * 10000 + mm * 100 + dd > ch.currentDate)
  fail(`This Aadhaar doesn't meet the server's minimum age (${ch.minAge}+). No proof was generated or sent.`);

const input = await buildCircuitInputs(qr, modulus, ch)
  .catch((e) => fail(`Can't use this QR: ${e.message}`));
console.log("Generating proof (this can take a while)...");
const { proof, publicSignals } = await prove(input).catch((e) =>
  fail(`The circuit refused to prove this QR (${String(e.message).trim().replace(/^Error: /, "")}). ` +
    "The line number refers to circuits/aadhaar_auth.circom. Nothing was sent to the server."));

const r = await fetch(`${server}/auth/verify`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ challengeId, proof, publicSignals }),
}).catch(() => fail(`Lost the connection to the auth server at ${server} before it could check the proof.`));
const body = await r.json();
if (!r.ok) fail(`The server rejected the proof (${r.status}): ${body.error ?? JSON.stringify(body)}`);
console.log(r.status, body);
process.exit(0);
