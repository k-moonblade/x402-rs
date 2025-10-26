#!/usr/bin/env tsx
/**
 * Generate a deterministic keypair from a passphrase/string
 *
 * ⚠️  WARNING: This script is for DEVELOPMENT/TESTING purposes only!
 * Do NOT use generated keys for production or real funds.
 *
 * Usage:
 *   npx tsx scripts/generate-keypair.ts
 *   npx tsx scripts/generate-keypair.ts "your seed phrase here"
 */

import { createHash } from 'crypto';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import * as readline from 'readline';

/**
 * Generate a private key from a string seed using SHA-256
 */
function generatePrivateKeyFromSeed(seed: string): Hex {
  // Hash the seed string to create a 32-byte private key
  const hash = createHash('sha256').update(seed).digest();

  // Convert to hex with 0x prefix
  const privateKey = `0x${hash.toString('hex')}` as Hex;

  return privateKey;
}

/**
 * Prompt user for input if not provided via CLI
 */
async function promptForSeed(): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question('Enter your seed phrase/string: ', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Display the generated keypair information
 */
function displayKeypair(seed: string, privateKey: Hex, address: string) {
  console.log('\n' + '='.repeat(70));
  console.log('🔑 Keypair Generated');
  console.log('='.repeat(70));
  console.log();
  console.log('Seed String:');
  console.log(`  "${seed}"`);
  console.log();
  console.log('Private Key:');
  console.log(`  ${privateKey}`);
  console.log();
  console.log('Address:');
  console.log(`  ${address}`);
  console.log();
  console.log('='.repeat(70));
  console.log();
  console.log('⚠️  IMPORTANT SECURITY WARNINGS:');
  console.log('  • Never share your private key with anyone');
  console.log('  • Do NOT use this for production or real funds');
  console.log('  • This is for DEVELOPMENT/TESTING only');
  console.log('  • Anyone with the seed can regenerate this key');
  console.log('='.repeat(70));
  console.log();

  // Show how to use with .env
  console.log('To use with your .env file, add:');
  console.log(`EVM_PRIVATE_KEY=${privateKey}`);
  console.log();
}

async function main() {
  console.log('\n🔐 Deterministic Keypair Generator\n');

  // Get seed from CLI arg or prompt
  let seed: string;

  if (process.argv.length > 2) {
    // Use CLI argument
    seed = process.argv.slice(2).join(' ');
  } else {
    // Prompt for input
    seed = await promptForSeed();
  }

  if (!seed || seed.trim().length === 0) {
    console.error('❌ Error: Seed string cannot be empty');
    process.exit(1);
  }

  // Generate private key from seed
  const privateKey = generatePrivateKeyFromSeed(seed);

  // Create account from private key
  const account = privateKeyToAccount(privateKey);

  // Display results
  displayKeypair(seed, privateKey, account.address);

  // Additional examples
  console.log('💡 Examples:');
  console.log('  Same seed always generates the same key:');
  console.log(`  npx tsx scripts/generate-keypair.ts "${seed}"`);
  console.log();
  console.log('  Try different seeds:');
  console.log('  npx tsx scripts/generate-keypair.ts "test-seed-1"');
  console.log('  npx tsx scripts/generate-keypair.ts "alice-dev-key"');
  console.log('  npx tsx scripts/generate-keypair.ts "bob-testing-123"');
  console.log();
}

main().catch((error) => {
  console.error('❌ Error:', error.message);
  process.exit(1);
});
