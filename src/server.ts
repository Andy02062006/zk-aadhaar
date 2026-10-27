import express from "express";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import * as snarkjs from "snarkjs";
import { appIdToField, modulusFromCert, pubkeyHash } from "./inputs.ts";

const APP_NAME = process.env.APP_NAME ?? "my-app";
const MIN_AGE = Number(process.env.MIN_AGE ?? 18);
const CHALLENGE_TTL_MS = 5 * 60_000;
const vkey = JSON.parse(readFileSync(process.env.VKEY ?? "build/verification_key.json", "utf8"));
const trustedHash = (await pubkeyHash(modulusFromCert(readFileSync(process.env.UIDAI_CERT ?? "uidai_offline_publickey.cer")))).toString();
const appId = appIdToField(APP_NAME).toString();

const challenges = new Map<string, { ch: Record<string, string | number>; exp: number }>();
const sessions = new Map<string, string>(); // token -> nullifier (the pseudonymous user id)
const istDate = () => Number(new Date(Date.now() + 5.5 * 3600_000).toISOString().slice(0, 10).replaceAll("-", ""));

const app = express();
app.use(express.json({ limit: "100kb" }));

app.post("/auth/challenge", (_req, res) => {
  const id = randomUUID();
  const ch = {
    appId, minAge: MIN_AGE, currentDate: istDate(),
    nonce: (BigInt("0x" + randomBytes(30).toString("hex"))).toString(),
    revealGender: 0, revealPincode: 0,
  };
  challenges.set(id, { ch, exp: Date.now() + CHALLENGE_TTL_MS });
  res.json({ challengeId: id, ...ch });
});

app.post("/auth/verify", async (req, res) => {
  const { challengeId, proof, publicSignals } = req.body ?? {};
  const rec = challenges.get(challengeId);
  challenges.delete(challengeId); // single use, even on failure
  if (!rec || rec.exp < Date.now()) return res.status(400).json({ error: "unknown or expired challenge" });
  if (!Array.isArray(publicSignals) || publicSignals.length !== 10) return res.status(400).json({ error: "bad public signals" });

  // snarkjs order: outputs, then public inputs in declaration order
  const [nullifier, , , pkHash, aId, nonce, minAge, curDate, revG, revP] = publicSignals.map(String);
  const c = rec.ch;
  const ok =
    pkHash === trustedHash && aId === String(c.appId) && nonce === String(c.nonce) &&
    minAge === String(c.minAge) && curDate === String(c.currentDate) &&
    revG === String(c.revealGender) && revP === String(c.revealPincode);
  if (!ok) return res.status(400).json({ error: "public inputs do not match challenge" });
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) return res.status(401).json({ error: "invalid proof" });

  const token = randomBytes(32).toString("hex");
  sessions.set(token, nullifier);
  res.json({ token, userId: nullifier });
});

app.get("/me", (req, res) => {
  const uid = sessions.get((req.headers.authorization ?? "").replace("Bearer ", ""));
  uid ? res.json({ userId: uid, ageVerified: `>=${MIN_AGE}` }) : res.status(401).json({ error: "unauthenticated" });
});

app.listen(3000, () => console.log("ZK-Aadhaar auth server on :3000"));
