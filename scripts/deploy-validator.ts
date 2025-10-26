#!/usr/bin/env tsx
/**
 * Self-contained script to deploy EIP-6492 Universal Signature Validator
 * to BSC Mainnet and BSC Testnet at address 0xdAcD51A54883eb67D95FAEb2BBfdC4a9a6BD2a3B
 *
 * Usage:
 *   npm install viem
 *   npx tsx scripts/deploy-validator.ts <mainnet|testnet|both> <private-key>
 *
 * Or with environment variable:
 *   PRIVATE_KEY=0x... npx tsx scripts/deploy-validator.ts both
 */

import {
  createWalletClient,
  createPublicClient,
  http,
  type Hex,
  type Address,
  type Chain,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { bsc, bscTestnet } from 'viem/chains';

// EIP-2470 Singleton Factory address (same across all EVM chains)
const SINGLETON_FACTORY: Address = '0xce0042B868300000d44A59004Da54A005ffdcf9f';

// Expected validator address after deployment
const EXPECTED_ADDRESS: Address = '0xdAcD51A54883eb67D95FAEb2BBfdC4a9a6BD2a3B';

// EIP-6492 Validator deployed bytecode (from BscScan)
const DEPLOYED_BYTECODE: Hex = '0x60808060405234601557610948908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c806376be4cea146100445780638f0684301461003f576398ef1ed81461003a575f80fd5b610202565b610143565b346100b65760a03660031901126100b657600435610061816100ba565b602435906044359067ffffffffffffffff82116100b65760209261008c6100ac9336906004016100cb565b906064359261009a846100f9565b608435946100a7866100f9565b6104e3565b6040519015158152f35b5f80fd5b6001600160a01b038116036100b657565b9181601f840112156100b65782359167ffffffffffffffff83116100b657602083818601950101116100b657565b801515036100b657565b60606003198201126100b65760043561011b816100ba565b91602435916044359067ffffffffffffffff82116100b65761013f916004016100cb565b9091565b346100b657602061015336610103565b93925f608060c0876040969596519889978897633b5f267560e11b8952600489019760018060a01b031688528a88015260a060408801528160a08801528387013783828287010152601f80199101168401019260016060820152015203815f305af180156101fd576020915f916101d0575b506040519015158152f35b6101f09150823d84116101f6575b6101e881836102b6565b810190610842565b5f6101c5565b503d6101de565b61043e565b346100b65760206100ac61021536610103565b929190916108ab565b601f1981019190821161022d57565b634e487b7160e01b5f52601160045260245ffd5b9092919283116100b6579190565b906020116100b65790602090565b906040116100b65760200190602090565b909392938483116100b65784116100b6578101920390565b359060208110610294575090565b5f199060200360031b1b1690565b634e487b7160e01b5f52604160045260245ffd5b90601f8019910116810190811067ffffffffffffffff8211176102d857604052565b6102a2565b67ffffffffffffffff81116102d857601f01601f191660200190565b929192610305826102dd565b9161031360405193846102b6565b8294818452818301116100b6578281602093845f960137010152565b9080601f830112156100b65781602061034a933591016102f9565b90565b916060838303126100b6578235610363816100ba565b92602081013567ffffffffffffffff81116100b6578361038491830161032f565b92604082013567ffffffffffffffff81116100b65761034a920161032f565b3d156103cd573d906103b4826102dd565b916103c260405193846102b6565b82523d5f602084013e565b606090565b805180835260209291819084018484015e5f828201840152601f01601f1916010190565b90602061034a9281815201906103d2565b908160209103126100b657516001600160e01b0319811681036100b65790565b60409061034a9392815281602082015201906103d2565b6040513d5f823e3d90fd5b1561045057565b60405162461bcd60e51b815260206004820152603a60248201527f5369676e617475726556616c696461746f72237265636f7665725369676e657260448201527f3a20696e76616c6964207369676e6174757265206c656e6774680000000000006064820152608490fd5b634e487b7160e01b5f52603260045260245ffd5b90604010156104de5760400190565b6104bb565b9490919293853b7f64926492649264926492649264926492649264926492649264926492649264926105286105228861051b8161021e565b818a61026e565b90610286565b1480156108325761054d61054561053e8961021e565b8989610241565b81019061034d565b918415801561082b575b6107e1575b50505b8182156107d8575b61068b57505050505061057c60418414610449565b6105ba6105b46105a6610592610522878761024f565b956105a0610522828861025d565b956104cf565b356001600160f81b03191690565b60f81c90565b9060ff8216601b811415908161067f575b5061061f576105fe5f93602095604051948594859094939260ff6060936080840197845216602083015260408201520152565b838052039060015afa156101fd575f516001600160a01b0390811691161490565b60405162461bcd60e51b815260206004820152602d60248201527f5369676e617475726556616c696461746f723a20696e76616c6964207369676e60448201526c617475726520762076616c756560981b606482015280608481015b0390fd5b601c915014155f6105cb565b60206106b49160409b99979598969a9b5180938192630b135d3f60e11b83528860048401610427565b03816001600160a01b038e165afa5f91816107a7575b5061071a5750506106d96103a3565b96159081610710575b5061070257604051636f2a959960e01b81528061067b88600483016103f6565b61034a9550600194966104e3565b905015155f6106e2565b96986001600160e01b0319909716630b135d3f60e11b149790969194939291908815908161079e575b5080610795575b610782575050505015918261077a575b5081610771575b506107695790565b5f526001601ffd5b9050155f610761565b91505f61075a565b909192935061034a9650600195506104e3565b5084151561074a565b9050155f610743565b6107ca91925060203d6020116107d1575b6107c281836102b6565b810190610407565b905f6106ca565b503d6107b8565b50821515610567565b81515f92839260209091019083906001600160a01b03165af16108026103a3565b901561080e578061055c565b604051639d0d6e2d60e01b815290819061067b90600483016103f6565b5086610557565b61083d3688886102f9565b61055f565b908160209103126100b6575161034a816100f9565b9493805f9460809460c09460018060a01b03168952602089015260a060408901528160a08901528388013783828288010152601f8019910116850101938260608201520152565b8051156104de5760200190565b6108cd602093946040519586948594633b5f267560e11b865260048601610857565b03815f305af15f9181610927575b5061034a57506108e96103a3565b8051600181036109245750600160f81b906001600160f81b03199061091f906109119061089e565b516001600160f81b03191690565b161490565b90fd5b61094191925060203d6020116101f6576101e881836102b6565b905f6108db56';

// Creation bytecode - for this contract, we use the deployed bytecode directly
// In CREATE2 deployment via singleton factory, we pass the init code
const INIT_CODE: Hex = DEPLOYED_BYTECODE;

// Salt for deterministic deployment
const SALT: Hex = '0x0000000000000000000000000000000000000000000000000000000000000000';

// Singleton Factory ABI - only the deploy function
const SINGLETON_FACTORY_ABI = [
  {
    inputs: [
      { name: '_initCode', type: 'bytes' },
      { name: '_salt', type: 'bytes32' }
    ],
    name: 'deploy',
    outputs: [{ name: 'createdContract', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
] as const;

interface DeploymentConfig {
  chain: Chain;
  rpcUrl?: string;
}

const NETWORKS: Record<string, DeploymentConfig> = {
  mainnet: {
    chain: bsc,
    rpcUrl: process.env.BSC_RPC_URL || 'https://bsc-mainnet.infura.io/v3/6520fe0dc61c41df8f87fc20d8593486',
  },
  testnet: {
    chain: bscTestnet,
    rpcUrl: process.env.BSC_TESTNET_RPC_URL || 'https://bsc-testnet.infura.io/v3/6520fe0dc61c41df8f87fc20d8593486',
  },
};

async function checkFactoryDeployed(
  publicClient: ReturnType<typeof createPublicClient>,
  networkName: string
): Promise<boolean> {
  console.log(`\n🔍 Checking if Singleton Factory is deployed on ${networkName}...`);

  const code = await publicClient.getBytecode({ address: SINGLETON_FACTORY });

  if (!code || code === '0x') {
    console.error(`❌ Error: EIP-2470 Singleton Factory not found at ${SINGLETON_FACTORY} on ${networkName}`);
    console.error('The factory must be deployed before you can use it.');
    return false;
  }

  console.log(`✅ Singleton Factory found on ${networkName}`);
  return true;
}

async function checkAlreadyDeployed(
  publicClient: ReturnType<typeof createPublicClient>,
  networkName: string
): Promise<boolean> {
  console.log(`🔍 Checking if validator is already deployed on ${networkName}...`);

  const code = await publicClient.getBytecode({ address: EXPECTED_ADDRESS });

  if (code && code !== '0x') {
    console.log(`✅ Validator already deployed at ${EXPECTED_ADDRESS} on ${networkName}`);
    return true;
  }

  console.log(`⚠️  Validator not yet deployed on ${networkName}`);
  return false;
}

async function deployToNetwork(
  networkName: string,
  config: DeploymentConfig,
  privateKey: Hex
): Promise<boolean> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`🚀 Deploying to ${networkName}`);
  console.log(`${'='.repeat(60)}`);
  console.log(`Chain: ${config.chain.name}`);
  console.log(`RPC URL: ${config.rpcUrl}`);
  console.log(`Expected Address: ${EXPECTED_ADDRESS}`);

  const account = privateKeyToAccount(privateKey);

  const publicClient = createPublicClient({
    chain: config.chain,
    transport: http(config.rpcUrl),
  });

  const walletClient = createWalletClient({
    account,
    chain: config.chain,
    transport: http(config.rpcUrl),
  });

  // Check if factory exists
  if (!(await checkFactoryDeployed(publicClient, networkName))) {
    return false;
  }

  // Check if already deployed
  if (await checkAlreadyDeployed(publicClient, networkName)) {
    return true;
  }

  console.log(`\n📝 Deploying validator contract...`);
  console.log(`Deployer: ${account.address}`);

  try {
    // Deploy using the singleton factory
    const hash = await walletClient.writeContract({
      address: SINGLETON_FACTORY,
      abi: SINGLETON_FACTORY_ABI,
      functionName: 'deploy',
      args: [INIT_CODE, SALT],
    });

    console.log(`✅ Transaction sent: ${hash}`);
    console.log(`⏳ Waiting for confirmation...`);

    // Wait for transaction receipt
    const receipt = await publicClient.waitForTransactionReceipt({ hash });

    if (receipt.status === 'reverted') {
      console.error(`❌ Transaction reverted on ${networkName}`);
      return false;
    }

    console.log(`✅ Transaction confirmed in block ${receipt.blockNumber}`);

    // Verify deployment
    const deployedCode = await publicClient.getBytecode({ address: EXPECTED_ADDRESS });

    if (deployedCode === DEPLOYED_BYTECODE) {
      console.log(`\n🎉 Successfully deployed validator to ${EXPECTED_ADDRESS} on ${networkName}!`);
      console.log(`\nVerification:`);
      console.log(`  Network: ${networkName}`);
      console.log(`  Address: ${EXPECTED_ADDRESS}`);
      console.log(`  TX Hash: ${hash}`);
      console.log(`  Block Explorer: ${config.chain.blockExplorers?.default.url}/address/${EXPECTED_ADDRESS}`);
      return true;
    } else {
      console.error(`❌ Deployment verification failed on ${networkName}`);
      console.error('Expected bytecode doesn\'t match deployed bytecode');
      return false;
    }
  } catch (error) {
    console.error(`❌ Deployment failed on ${networkName}:`, error);
    return false;
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.log(`
Usage: npx tsx scripts/deploy-validator.ts <mainnet|testnet|both> [private-key]

Arguments:
  mainnet|testnet|both  - Which network(s) to deploy to
  private-key           - Your private key (with 0x prefix)
                         Can also be set via PRIVATE_KEY env var

Environment variables:
  PRIVATE_KEY           - Your private key (alternative to CLI arg)
  BSC_RPC_URL          - Custom BSC mainnet RPC URL
  BSC_TESTNET_RPC_URL  - Custom BSC testnet RPC URL

Examples:
  PRIVATE_KEY=0x... npx tsx scripts/deploy-validator.ts testnet
  npx tsx scripts/deploy-validator.ts both 0x1234...
  npx tsx scripts/deploy-validator.ts mainnet 0x1234...
`);
    process.exit(1);
  }

  const network = args[0];
  const privateKey = (args[1] || process.env.PRIVATE_KEY) as Hex;

  if (!privateKey || !privateKey.startsWith('0x')) {
    console.error('❌ Error: Private key must be provided and start with 0x');
    process.exit(1);
  }

  console.log('🔧 EIP-6492 Validator Deployment Script');
  console.log('📋 Configuration:');
  console.log(`  Singleton Factory: ${SINGLETON_FACTORY}`);
  console.log(`  Target Address: ${EXPECTED_ADDRESS}`);

  const results: boolean[] = [];

  switch (network) {
    case 'mainnet':
      results.push(await deployToNetwork('BSC Mainnet', NETWORKS.mainnet, privateKey));
      break;
    case 'testnet':
      results.push(await deployToNetwork('BSC Testnet', NETWORKS.testnet, privateKey));
      break;
    case 'both':
      results.push(await deployToNetwork('BSC Testnet', NETWORKS.testnet, privateKey));
      results.push(await deployToNetwork('BSC Mainnet', NETWORKS.mainnet, privateKey));
      break;
    default:
      console.error(`❌ Error: Invalid network option '${network}'`);
      console.error('Valid options: mainnet, testnet, both');
      process.exit(1);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log('📊 Deployment Summary');
  console.log(`${'='.repeat(60)}`);

  const successCount = results.filter(r => r).length;
  const totalCount = results.length;

  if (successCount === totalCount) {
    console.log(`✅ All deployments successful (${successCount}/${totalCount})`);
    process.exit(0);
  } else {
    console.log(`⚠️  Some deployments failed (${successCount}/${totalCount} successful)`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('❌ Unexpected error:', error);
  process.exit(1);
});
