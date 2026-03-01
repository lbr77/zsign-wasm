# TypeScript Wrapper

This directory contains a TypeScript wrapper for the zsign-wasm-resigner package, providing enhanced type safety and a more idiomatic TypeScript API.

## Features

- Full TypeScript type definitions
- Improved error handling with initialization checks
- Clean and intuitive API design
- Better separation of concerns with dedicated client classes

## Installation

```bash
npm install zsign-wasm-resigner
```

## Usage

### Signing Mach-O Files

```typescript
import { createClient } from 'zsign-wasm-resigner/wrapper';
import { readFileSync, writeFileSync } from 'fs';

async function signMachO() {
  const client = await createClient();

  const machO = readFileSync('input.dylib');
  const cert = readFileSync('certificate.cer');
  const pkey = readFileSync('private.key');

  const result = client.signMachO(machO, {
    cert,
    pkey,
    adhoc: true
  });

  writeFileSync('output.dylib', result.data);
}
```

### Resigning IPA Files

```typescript
import { createResigner } from 'zsign-wasm-resigner/wrapper';
import { readFileSync, writeFileSync } from 'fs';

async function resignIpa() {
  const resigner = await createResigner();

  const ipa = readFileSync('input.ipa');
  const cert = readFileSync('certificate.cer');
  const pkey = readFileSync('private.key');
  const prov = readFileSync('profile.mobileprovision');

  const result = await resigner.signIpa(ipa, {
    cert,
    pkey,
    prov,
    bundleId: 'com.example.app',
    displayName: 'My App',
    adhoc: true
  });

  writeFileSync('output.ipa', result.data);
}
```

## API Reference

### ZsignClient

A client for signing Mach-O files.

#### `ZsignClient.create(options?): Promise<ZsignClient>`

Creates a new ZsignClient instance.

#### `client.signMachO(inputMachO, options?): MachOSignResult`

Signs a Mach-O file.

#### `client.version(): string`

Returns the version string.

#### `client.setLogLevel(level: number): number`

Sets the logging level.

### ZsignResigner

A client for resigning IPA files.

#### `ZsignResigner.create(options?): Promise<ZsignResigner>`

Creates a new ZsignResigner instance.

#### `resigner.signMachO(inputMachO, options?): MachOSignResult`

Signs a Mach-O file.

#### `resigner.signIpa(inputIpa, options?): Promise<IpaSignResult>`

Resigns an IPA file.

#### `resigner.version(): string`

Returns the version string.

#### `resigner.setLogLevel(level: number): number`

Sets the logging level.

### Options

#### SignMachOOptions

- `cert?: Uint8Array | ArrayBuffer` - Certificate data
- `pkey?: Uint8Array | ArrayBuffer` - Private key data
- `prov?: Uint8Array | ArrayBuffer` - Provisioning profile
- `entitlements?: Uint8Array | ArrayBuffer` - Entitlements plist
- `password?: string` - Password for encrypted certificate
- `adhoc?: boolean` - Enable ad-hoc signing
- `sha256Only?: boolean` - Use SHA256 only
- `forceSign?: boolean` - Force re-signing

#### SignIpaOptions

Extends `SignMachOOptions` with additional options:

- `bundleId?: string` - New bundle identifier
- `bundleVersion?: string` - New bundle version
- `displayName?: string` - New display name
- `weakInject?: boolean` - Enable weak injection
- `enableCache?: boolean` - Enable caching
- `zipLevel?: number` - ZIP compression level (0-9)

## Certificate Chain Builder

This package includes utilities for building complete certificate chains for Apple code signing.

### Why Certificate Chains?

When signing iOS apps, you need a complete certificate chain:
1. Developer Certificate
2. WWDR Intermediate Certificate (Apple Worldwide Developer Relations Certification Authority)
3. Apple Root CA (optional, usually already trusted by the system)

Without the complete chain, signatures may fail verification with `Authority=(unavailable)`.

### Quick Start

```typescript
import { createResigner, buildCertificateChainDER } from 'zsign-wasm-resigner-wrapper';
import { readFileSync, writeFileSync } from 'fs';

async function signWithCompleteChain() {
  const resigner = await createResigner();

  // Load developer certificate
  const developerCert = readFileSync('developer.cer');

  // Automatically download WWDR and build complete chain
  const certChain = await buildCertificateChainDER({
    developerCert
  });

  // Sign with complete certificate chain
  const ipa = readFileSync('input.ipa');
  const pkey = readFileSync('private.key');
  const prov = readFileSync('profile.mobileprovision');

  const result = await resigner.signIpa(ipa, {
    cert: certChain,  // Complete chain: Developer + WWDR
    pkey,
    prov,
    adhoc: false,
    forceSign: true
  });

  writeFileSync('output.ipa', result.data);
}
```

### API Reference

#### `buildCertificateChainDER(options): Promise<Uint8Array>`

Builds certificate chain in DER format (binary), suitable for passing to zsign.

```typescript
const certChain = await buildCertificateChainDER({
  developerCert: Uint8Array,     // Required: Your developer certificate
  wwdrCert?: Uint8Array,         // Optional: WWDR cert (auto-downloaded if omitted)
  rootCert?: Uint8Array,         // Optional: Root CA (auto-downloaded if omitted)
  includeRootCA?: boolean        // Optional: Include Root CA (default: false)
});
```

#### `buildCertificateChain(options): Promise<string>`

Builds certificate chain in PEM format (text), suitable for saving to files or OpenSSL verification.

```typescript
const pemChain = await buildCertificateChain({
  developerCert,
  includeRootCA: true
});

// Save to file
writeFileSync('chain.pem', pemChain);
```

#### `CertificateChainBuilder` Class

For advanced usage with more control:

```typescript
import { CertificateChainBuilder } from 'zsign-wasm-resigner-wrapper';

const builder = new CertificateChainBuilder();

// Manually download certificates
const wwdr = await builder.downloadWWDR();
const root = await builder.downloadRootCA();

// Convert DER to PEM
const pem = builder.derToPem(wwdr, 'CERTIFICATE');

// Build chain with custom options
const chain = await builder.buildCertificateChain({
  developerCert,
  wwdrCert: wwdr,
  includeRootCA: false
});
```

### Examples

See [CERTCHAIN.md](./CERTCHAIN.md) for detailed examples:
- Automatically downloading WWDR certificates
- Using local certificate files
- Exporting PEM format chains
- Verifying chains with OpenSSL

## Building

```bash
npm run build
```

This will compile the TypeScript code to JavaScript in the `dist/` directory.

## License

MIT