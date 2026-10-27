# ZK-Aadhaar Auth

Log in with a zero-knowledge proof of an Aadhaar **Secure QR code**. The QR (signed by UIDAI) never leaves the user's device;
the server learns only a pseudonymous per-app ID, "age >= N", and any attributes the user agrees to reveal (gender, pincode).

## Flow
1. `POST /auth/challenge` -> server returns `{challengeId, nonce, appId, minAge, currentDate, reveal flags}`.
2. Client parses the QR locally and proves in-circuit that: UIDAI's RSA-2048/SHA-256 signature over the QR data is valid for the
   trusted UIDAI key; DOB satisfies `minAge`; the nullifier is correct; the proof is bound to `nonce`.
3. `POST /auth/verify` -> server checks every public signal against the stored challenge (single-use, 5 min TTL), the pinned
   UIDAI key hash, then `groth16.verify`. Returns a session token. `userId` = nullifier.

## Design notes
- **Nullifier** = Poseidon(appId, last-4, DOB, gender, pincode, first 16 bytes of name). Stable across QR re-downloads (the QR's
  timestamp changes, these fields don't), different per app (no cross-site linking), one account per Aadhaar (Sybil resistance).
- **Trust anchor**: the Poseidon hash of UIDAI's modulus is a public input; the server pins it from UIDAI's published certificate.
- **Replay**: nonce is public input, challenge is deleted on first use.

## Setup
```
npm install
# put UIDAI's public certificate (from uidai.gov.in, offline e-KYC / Secure QR section) at ./uidai_offline_publickey.cer
npm test                  # off-chain tests (no circom needed)
npm run setup             # needs circom >= 2.1.5; downloads a 2^21 ptau (~2 GB); circuit is ~1M constraints
npm run server
npm run client -- my_qr.txt   # my_qr.txt = the numeric string decoded from the mAadhaar / Aadhaar PDF QR
```

## Status: what is and isn't verified
**Tested (`npm test`):** QR parsing, SHA padding, field offsets and delimiter counts, PKCS#1 EM / hash-chunk conventions used by the
circuit, nullifier stability — using a *synthetic QR signed with a test key*.
**Not tested:** the Circom circuit has **not been compiled or proven** (no circom in the build sandbox), and nothing has been run
against a real Aadhaar QR. Before relying on it:
1. Compile; confirm `RSAVerifier65537`'s message-chunk convention in your pinned `@zk-email/circuits` version (the test confirms
   my chunking is the standard little-endian 121-bit limbs; adjust if that library version differs).
2. Check the field layout against a real QR (field indices 2/3/4/5/11 follow UIDAI's published format).
3. Replace the single-party zkey contribution with a real ceremony; get an independent audit of the circuit.

## Limitations
- `MAX_BYTES = 1536`: payloads with larger photos are rejected (raise it and the ptau size; cost grows ~linearly).
- Requires full `DD-MM-YYYY` DOB (some Aadhaars have year only). Name is ASCII/first 16 bytes for the nullifier.
- Nullifier inputs have finite entropy; someone who knows a person's details can test whether they are a user of your app.
- Secure QR is offline-valid: a stolen/shared QR image can be used by someone else. Add a liveness/device-binding step for high-value use.
- Aadhaar Act / DPDP: don't collect or store the QR or Aadhaar number; check legal requirements for your use case.
