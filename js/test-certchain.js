/**
 * Simple test for certificate chain builder
 */

const { CertificateChainBuilder } = require('./dist/certchain');

async function testCertChainBuilder() {
  console.log('Testing CertificateChainBuilder...\n');

  const builder = new CertificateChainBuilder();

  // Test 1: Download WWDR
  console.log('Test 1: Downloading WWDR certificate...');
  try {
    const wwdr = await builder.downloadWWDR();
    console.log(`  ✓ Downloaded WWDR (${wwdr.length} bytes)`);
  } catch (error) {
    console.error('  ✗ Failed to download WWDR:', error.message);
  }

  // Test 2: Download Root CA
  console.log('\nTest 2: Downloading Apple Root CA...');
  try {
    const root = await builder.downloadRootCA();
    console.log(`  ✓ Downloaded Root CA (${root.length} bytes)`);
  } catch (error) {
    console.error('  ✗ Failed to download Root CA:', error.message);
  }

  // Test 3: DER to PEM conversion
  console.log('\nTest 3: DER to PEM conversion...');
  try {
    const wwdr = await builder.downloadWWDR();
    const pem = builder.derToPem(wwdr, 'CERTIFICATE');
    const hasHeader = pem.includes('-----BEGIN CERTIFICATE-----');
    const hasFooter = pem.includes('-----END CERTIFICATE-----');
    if (hasHeader && hasFooter) {
      console.log('  ✓ DER to PEM conversion successful');
      console.log(`  PEM length: ${pem.length} characters`);
    } else {
      console.error('  ✗ Invalid PEM format');
    }
  } catch (error) {
    console.error('  ✗ DER to PEM conversion failed:', error.message);
  }

  console.log('\nAll tests completed!');
}

testCertChainBuilder().catch(console.error);