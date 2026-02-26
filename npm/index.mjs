import createApi from './api.cjs';
import wasmBundle from '../dist/zsign-wasm.min.js';

const api = createApi(wasmBundle);

export const {
  ZsignWasmResigner,
  ZsignWasmClient,
  createZsignModule,
  createEmbeddedZsignModule,
  createResigner
} = api;

export default api;
