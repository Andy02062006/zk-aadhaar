import * as snarkjs from "snarkjs";
export async function prove(input: object, wasm = "build/aadhaar_auth_js/aadhaar_auth.wasm", zkey = "build/aadhaar_auth.zkey") {
  return snarkjs.groth16.fullProve(input, wasm, zkey);
}
