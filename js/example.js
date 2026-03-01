const { ZsignClient, ZsignResigner } = require('./dist/index');
const fs = require('fs');
const path = require('path');

async function main() {
  try {
    console.log('Creating ZsignClient...');
    const client = await ZsignClient.create();

    console.log('Version:', client.version());

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
      path.join(__dirname, '../test/dylib/bin/demo1-signed-wrapper.dylib'),
      Buffer.from(result.data)
    );

    console.log('Mach-O file signed successfully!');
    console.log('Output saved to: test/dylib/bin/demo1-signed-wrapper.dylib');
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

main();