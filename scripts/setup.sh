#!/usr/bin/env bash
# Requires: circom >= 2.1.5, node, and a Powers of Tau file with power >= 21 (~1.1M constraints).
set -euo pipefail
mkdir -p build
PTAU=${PTAU:-build/powersOfTau28_hez_final_20.ptau}
[ -f "$PTAU" ] || curl -L -o "$PTAU" https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau
circom circuits/aadhaar_auth.circom --r1cs --wasm --sym -l node_modules -o build
npx snarkjs groth16 setup build/aadhaar_auth.r1cs "$PTAU" build/aadhaar_auth_0.zkey
# Production: run a multi-party contribution ceremony instead of a single contribution.
npx snarkjs zkey contribute build/aadhaar_auth_0.zkey build/aadhaar_auth.zkey --name="dev" -e="$(head -c 32 /dev/urandom | xxd -p)"
npx snarkjs zkey export verificationkey build/aadhaar_auth.zkey build/verification_key.json
echo "Done. Start the server with: npm run server"
