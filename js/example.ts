import { createClient, createResigner } from './src/index';
import * as fs from 'fs';
import * as path from 'path';

async function signMachOExample() {
  console.log('=== Mach-O Signing Example ===');

  const client = await createClient();
  console.log('Client version:', client.version());

  const inputMacho = fs.readFileSync(
    path.join(__dirname, '../test/dylib/bin/demo1.dylib')
  );
  const cert = fs.readFileSync(
    path.join(__dirname, '../test/assets/generated/local_test.cer')
  );
  const key = fs.readFileSync(
    path.join(__dirname, '../test/assets/generated/local_test.key')
  );

  console.log('Signing Mach-O file...');
  const result = client.signMachO(inputMacho, {
    cert,
    pkey: key,
    adhoc: true
  });

  fs.writeFileSync(
    path.join(__dirname, '../test/dylib/bin/demo1-signed-ts.dylib'),
    Buffer.from(result.data)
  );

  console.log('Mach-O file signed successfully!');
  console.log('Output: test/dylib/bin/demo1-signed-ts.dylib\n');
}

async function resignIpaExample() {
  console.log('=== IPA Resigning Example ===');

  const resigner = await createResigner();
  console.log('Resigner version:', resigner.version());

  // This is an example - you would need an actual IPA file
  // const ipa = fs.readFileSync('input.ipa');
  // const cert = fs.readFileSync('certificate.cer');
  // const pkey = fs.readFileSync('private.key');
  // const prov = fs.readFileSync('profile.mobileprovision');

  // console.log('Resigning IPA file...');
  // const result = await resigner.signIpa(ipa, {
  //   cert,
  //   pkey: key,
  //   prov,
  //   bundleId: 'com.example.resigned',
  //   displayName: 'Resigned App',
  //   adhoc: true
  // });

  // fs.writeFileSync('output.ipa', Buffer.from(result.data));
  console.log('(IPA resigning example - commented out for demo purposes)\n');
}

async function main() {
  try {
    await signMachOExample();
    await resignIpaExample();
    console.log('All examples completed successfully!');
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

main();