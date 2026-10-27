pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";

// Reads L bytes starting at private index `start`, plus the byte before `start`
// and the field counter (number of 0xFF delimiters seen so far) at `start`.
template Window(N, L) {
    signal input data[N];
    signal input fieldIdx[N];
    signal input start;
    signal output out[L];
    signal output prev;
    signal output fidx;

    component eq[N];
    signal oh[N];
    var ohSum = 0;
    for (var q = 0; q < N; q++) {
        eq[q] = IsEqual();
        eq[q].in[0] <== q;
        eq[q].in[1] <== start;
        oh[q] <== eq[q].out;
        ohSum += oh[q];
    }
    ohSum === 1; // start must be inside the buffer

    signal t[L][N];
    for (var j = 0; j < L; j++) {
        var s = 0;
        for (var q = 0; q + j < N; q++) { t[j][q] <== oh[q] * data[q + j]; s += t[j][q]; }
        out[j] <== s;
    }
    signal tp[N];
    signal tf[N];
    var sp = 0;
    var sf = 0;
    tp[0] <== 0;
    for (var q = 1; q < N; q++) { tp[q] <== oh[q] * data[q - 1]; sp += tp[q]; }
    for (var q = 0; q < N; q++) { tf[q] <== oh[q] * fieldIdx[q]; sf += tf[q]; }
    prev <== sp;
    fidx <== sf;
}

template Digit() {
    signal input b;
    signal output v;
    component ge = GreaterEqThan(8); ge.in[0] <== b; ge.in[1] <== 48; ge.out === 1;
    component le = LessEqThan(8);    le.in[0] <== b; le.in[1] <== 57; le.out === 1;
    v <== b - 48;
}

// Aadhaar Secure QR layout: text fields separated by 0xFF.
//   0 version | 1 email/mobile flag | 2 referenceId (last4 + timestamp) | 3 name |
//   4 DOB (DD-MM-YYYY) | 5 gender | ... | 11 pincode | ...
template AadhaarAuth(MAX_BYTES) {
    var N = 121;
    var K = 17;
    var NAME_BYTES = 16;

    // ---- public (snarkjs lists outputs first, then these in this order) ----
    signal input pubkeyHash;     // Poseidon hash of the UIDAI RSA modulus
    signal input appId;          // scopes the nullifier to one relying party
    signal input nonce;          // server challenge -> anti-replay
    signal input minAge;
    signal input currentDate;    // YYYYMMDD (IST)
    signal input revealGender;   // 0/1
    signal input revealPincode;  // 0/1

    // ---- private ----
    signal input data[MAX_BYTES];       // SHA-256-padded signed QR payload
    signal input dataLenPadded;
    signal input signature[K];
    signal input modulus[K];
    signal input refStart;
    signal input nameStart;
    signal input dobStart;
    signal input genderStart;
    signal input pincodeStart;

    signal output nullifier;
    signal output genderOut;
    signal output pincodeOut;

    // 1. The RSA key must be the trusted UIDAI key
    component ph1 = Poseidon(9);
    component ph2 = Poseidon(8);
    component ph  = Poseidon(2);
    for (var i = 0; i < 9; i++) ph1.inputs[i] <== modulus[i];
    for (var i = 0; i < 8; i++) ph2.inputs[i] <== modulus[9 + i];
    ph.inputs[0] <== ph1.out;
    ph.inputs[1] <== ph2.out;
    ph.out === pubkeyHash;

    // 2. SHA-256 of signed payload + RSA-2048 PKCS#1 v1.5 verification
    component sha = Sha256Bytes(MAX_BYTES);
    for (var i = 0; i < MAX_BYTES; i++) sha.paddedIn[i] <== data[i];
    sha.paddedInLength <== dataLenPadded;

    component rsa = RSAVerifier65537(N, K);
    for (var c = 0; c < K; c++) {
        var acc = 0;
        var pw = 1;
        for (var b = 0; b < N; b++) {
            var pos = N * c + b;
            if (pos < 256) acc += sha.out[255 - pos] * pw; // SHA out is MSB-first
            pw = pw * 2;
        }
        rsa.message[c] <== acc;
        rsa.signature[c] <== signature[c];
        rsa.modulus[c] <== modulus[c];
    }

    // 3. Field index of every byte (count of 0xFF before it)
    component isD[MAX_BYTES];
    signal fieldIdx[MAX_BYTES + 1];
    fieldIdx[0] <== 0;
    for (var p = 0; p < MAX_BYTES; p++) {
        isD[p] = IsEqual();
        isD[p].in[0] <== data[p];
        isD[p].in[1] <== 255;
        fieldIdx[p + 1] <== fieldIdx[p] + isD[p].out;
    }

    // 4. Extract fields; each must start right after a delimiter, in the right field
    component wRef = Window(MAX_BYTES, 4);
    component wName = Window(MAX_BYTES, NAME_BYTES);
    component wDob = Window(MAX_BYTES, 11);
    component wGen = Window(MAX_BYTES, 2);
    component wPin = Window(MAX_BYTES, 7);
    wRef.start <== refStart; wName.start <== nameStart; wDob.start <== dobStart;
    wGen.start <== genderStart; wPin.start <== pincodeStart;
    for (var p = 0; p < MAX_BYTES; p++) {
        wRef.data[p] <== data[p];  wRef.fieldIdx[p] <== fieldIdx[p];
        wName.data[p] <== data[p]; wName.fieldIdx[p] <== fieldIdx[p];
        wDob.data[p] <== data[p];  wDob.fieldIdx[p] <== fieldIdx[p];
        wGen.data[p] <== data[p];  wGen.fieldIdx[p] <== fieldIdx[p];
        wPin.data[p] <== data[p];  wPin.fieldIdx[p] <== fieldIdx[p];
    }
    wRef.prev === 255;  wRef.fidx === 2;
    wName.prev === 255; wName.fidx === 3;
    wDob.prev === 255;  wDob.fidx === 4;
    wGen.prev === 255;  wGen.fidx === 5;
    wPin.prev === 255;  wPin.fidx === 11;
    wDob.out[10] === 255; // DOB is exactly 10 chars
    wGen.out[1] === 255;  // gender is exactly 1 char
    wPin.out[6] === 255;  // pincode is exactly 6 digits

    component pd[6];
    var pinNum = 0;
    var pw10 = 1;
    for (var i = 0; i < 6; i++) { pd[i] = Digit(); pd[i].b <== wPin.out[i]; pinNum += pd[i].v * pw10; pw10 *= 10; }

    // 5. DOB -> age check (DD-MM-YYYY)
    component dd[8];
    var idxMap[8] = [0, 1, 3, 4, 6, 7, 8, 9];
    for (var i = 0; i < 8; i++) { dd[i] = Digit(); dd[i].b <== wDob.out[idxMap[i]]; }
    wDob.out[2] === 45;
    wDob.out[5] === 45;
    signal day;   day   <== dd[0].v * 10 + dd[1].v;
    signal month; month <== dd[2].v * 10 + dd[3].v;
    signal year;  year  <== dd[4].v * 1000 + dd[5].v * 100 + dd[6].v * 10 + dd[7].v;
    component ageCap = LessEqThan(8); ageCap.in[0] <== minAge; ageCap.in[1] <== 150; ageCap.out === 1;
    signal dobPlus;
    dobPlus <== (year + minAge) * 10000 + month * 100 + day;
    component ageOk = LessEqThan(32);
    ageOk.in[0] <== dobPlus;
    ageOk.in[1] <== currentDate;
    ageOk.out === 1;

    // 6. Selective disclosure
    revealGender * (revealGender - 1) === 0;
    revealPincode * (revealPincode - 1) === 0;
    genderOut  <== revealGender * wGen.out[0];
    pincodeOut <== revealPincode * pinNum;

    // 7. Nullifier: stable per person per app, unlinkable across apps
    component nd[4];
    var refPack = 0; var pw1 = 1;
    for (var i = 0; i < 4; i++) { nd[i] = Digit(); nd[i].b <== wRef.out[i]; refPack += nd[i].v * pw1; pw1 *= 10; }
    var dobPack = 0; var pw256 = 1;
    for (var i = 0; i < 10; i++) { dobPack += wDob.out[i] * pw256; pw256 *= 256; }
    component nIsD[NAME_BYTES];
    signal alive[NAME_BYTES + 1];
    signal masked[NAME_BYTES];
    alive[0] <== 1;
    var namePack = 0; var pwn = 1;
    for (var i = 0; i < NAME_BYTES; i++) {
        nIsD[i] = IsEqual();
        nIsD[i].in[0] <== wName.out[i];
        nIsD[i].in[1] <== 255;
        alive[i + 1] <== alive[i] * (1 - nIsD[i].out);
        masked[i] <== alive[i + 1] * wName.out[i];
        namePack += masked[i] * pwn; pwn *= 256;
    }
    component nul = Poseidon(6);
    nul.inputs[0] <== appId;
    nul.inputs[1] <== refPack;
    nul.inputs[2] <== dobPack;
    nul.inputs[3] <== wGen.out[0];
    nul.inputs[4] <== pinNum;
    nul.inputs[5] <== namePack;
    nullifier <== nul.out;

    // 8. Bind the proof to the server nonce
    signal nonceSq;
    nonceSq <== nonce * nonce;
}

component main { public [pubkeyHash, appId, nonce, minAge, currentDate, revealGender, revealPincode] } = AadhaarAuth(1152);
