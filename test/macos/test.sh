#!/bin/bash
set -u

ZSIGN_JS="../../bin/zsign-wasm.js"
SAMPLES=(../dylib/bin/demo1.dylib ../dylib/bin/demo2.dylib)

CERT_FILE="${CERT_FILE:-../assets/test.cer}"
PKEY_FILE="${PKEY_FILE:-../assets/test.p12}"
PROV_FILE="${PROV_FILE:-../assets/test.mobileprovision}"
PKEY_PASSWORD="${PKEY_PASSWORD:-}"

if [[ ! -f "$ZSIGN_JS" ]]; then
    echo "Missing signer: $ZSIGN_JS"
    echo "Build first: cd build/wasm && make"
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "node not found."
    exit 1
fi

USE_CERT_MODE=0
if [[ -f "$PKEY_FILE" && -f "$PROV_FILE" ]]; then
    USE_CERT_MODE=1
fi

for file in "${SAMPLES[@]}"; do
    if [[ ! -f "$file" ]]; then
        continue
    fi

    out="${file}.signed"
    rm -f "$out"

    echo -n "$file: "

    if [[ "$USE_CERT_MODE" -eq 1 ]]; then
        if [[ -f "$CERT_FILE" ]]; then
            node - "$ZSIGN_JS" "$file" "$out" "$CERT_FILE" "$PKEY_FILE" "$PROV_FILE" "$PKEY_PASSWORD" <<'NODE' >/dev/null 2>&1
const fs = require('fs');
const createZsignModule = require(process.argv[2]);
const inputPath = process.argv[3];
const outputPath = process.argv[4];
const certPath = process.argv[5];
const pkeyPath = process.argv[6];
const provPath = process.argv[7];
const passwd = process.argv[8] || '';
createZsignModule().then((mod) => {
  const heap8 = mod.getHeapU8();
  const heap32 = mod.getHeapU32();

  const input = fs.readFileSync(inputPath);
  const cert = fs.readFileSync(certPath);
  const pkey = fs.readFileSync(pkeyPath);
  const prov = fs.readFileSync(provPath);

  function toHeap(buf) {
    const p = mod._malloc(buf.length);
    heap8.set(buf, p);
    return p;
  }

  const inPtr = toHeap(input);
  const certPtr = toHeap(cert);
  const pkeyPtr = toHeap(pkey);
  const provPtr = toHeap(prov);
  const outPtrPtr = mod._malloc(4);
  const outLenPtr = mod._malloc(4);
  heap32[outPtrPtr >> 2] = 0;
  heap32[outLenPtr >> 2] = 0;

  const ret = mod._zsign_sign_macho_mem(
    inPtr, input.length,
    certPtr, cert.length,
    pkeyPtr, pkey.length,
    provPtr, prov.length,
    0,
    0, 0,
    0, 0, 1,
    outPtrPtr, outLenPtr
  );

  if (ret === 0) {
    const outPtr = heap32[outPtrPtr >> 2];
    const outLen = heap32[outLenPtr >> 2];
    fs.writeFileSync(outputPath, Buffer.from(heap8.subarray(outPtr, outPtr + outLen)));
    mod._zsign_free_buffer(outPtr);
  }

  mod._free(inPtr);
  mod._free(certPtr);
  mod._free(pkeyPtr);
  mod._free(provPtr);
  mod._free(outPtrPtr);
  mod._free(outLenPtr);
  process.exit(ret === 0 ? 0 : 1);
}).catch(() => process.exit(1));
NODE
        else
            node - "$ZSIGN_JS" "$file" "$out" "$PKEY_FILE" "$PROV_FILE" "$PKEY_PASSWORD" <<'NODE' >/dev/null 2>&1
const fs = require('fs');
const createZsignModule = require(process.argv[2]);
const inputPath = process.argv[3];
const outputPath = process.argv[4];
const pkeyPath = process.argv[5];
const provPath = process.argv[6];
const passwd = process.argv[7] || '';
createZsignModule().then((mod) => {
  const heap8 = mod.getHeapU8();
  const heap32 = mod.getHeapU32();

  const input = fs.readFileSync(inputPath);
  const pkey = fs.readFileSync(pkeyPath);
  const prov = fs.readFileSync(provPath);

  function toHeap(buf) {
    const p = mod._malloc(buf.length);
    heap8.set(buf, p);
    return p;
  }

  const inPtr = toHeap(input);
  const pkeyPtr = toHeap(pkey);
  const provPtr = toHeap(prov);
  const outPtrPtr = mod._malloc(4);
  const outLenPtr = mod._malloc(4);
  heap32[outPtrPtr >> 2] = 0;
  heap32[outLenPtr >> 2] = 0;

  const ret = mod._zsign_sign_macho_mem(
    inPtr, input.length,
    0, 0,
    pkeyPtr, pkey.length,
    provPtr, prov.length,
    0,
    0, 0,
    0, 0, 1,
    outPtrPtr, outLenPtr
  );

  if (ret === 0) {
    const outPtr = heap32[outPtrPtr >> 2];
    const outLen = heap32[outLenPtr >> 2];
    fs.writeFileSync(outputPath, Buffer.from(heap8.subarray(outPtr, outPtr + outLen)));
    mod._zsign_free_buffer(outPtr);
  }

  mod._free(inPtr);
  mod._free(pkeyPtr);
  mod._free(provPtr);
  mod._free(outPtrPtr);
  mod._free(outLenPtr);
  process.exit(ret === 0 ? 0 : 1);
}).catch(() => process.exit(1));
NODE
        fi
    else
        node - "$ZSIGN_JS" "$file" "$out" <<'NODE' >/dev/null 2>&1
const fs = require('fs');
const createZsignModule = require(process.argv[2]);
const inputPath = process.argv[3];
const outputPath = process.argv[4];
createZsignModule().then((mod) => {
  const heap8 = mod.getHeapU8();
  const heap32 = mod.getHeapU32();
  const input = fs.readFileSync(inputPath);

  const inPtr = mod._malloc(input.length);
  heap8.set(input, inPtr);
  const outPtrPtr = mod._malloc(4);
  const outLenPtr = mod._malloc(4);
  heap32[outPtrPtr >> 2] = 0;
  heap32[outLenPtr >> 2] = 0;

  const ret = mod._zsign_sign_macho_mem(
    inPtr, input.length,
    0, 0,
    0, 0,
    0, 0,
    0,
    0, 0,
    1, 0, 1,
    outPtrPtr, outLenPtr
  );

  if (ret === 0) {
    const outPtr = heap32[outPtrPtr >> 2];
    const outLen = heap32[outLenPtr >> 2];
    fs.writeFileSync(outputPath, Buffer.from(heap8.subarray(outPtr, outPtr + outLen)));
    mod._zsign_free_buffer(outPtr);
  }

  mod._free(inPtr);
  mod._free(outPtrPtr);
  mod._free(outLenPtr);
  process.exit(ret === 0 ? 0 : 1);
}).catch(() => process.exit(1));
NODE
    fi

    if [[ $? -eq 0 && -f "$out" ]]; then
        echo -e "\033[32mOK.\033[0m"
    else
        echo -e "\033[31m!!!FAILED!!!\033[0m"
    fi
done
