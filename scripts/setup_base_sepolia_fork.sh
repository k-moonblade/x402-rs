#!/bin/bash
# Setup script for Base Sepolia Anvil fork with USDC minting
# Usage: ./scripts/setup_base_sepolia_fork.sh <TEST_ADDRESS>

set -e

BASE_SEPOLIA_RPC="https://base-sepolia.infura.io/v3/6520fe0dc61c41df8f87fc20d8593486"
USDC_ADDRESS="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
ANVIL_PORT=8545

# Test address to fund
TEST_ADDRESS=${1:-""}

if [ -z "$TEST_ADDRESS" ]; then
    echo "Usage: $0 <TEST_ADDRESS>"
    echo "Example: $0 0x1234567890123456789012345678901234567890"
    exit 1
fi

echo "🔧 Setting up Base Sepolia fork on port $ANVIL_PORT"

# Start Anvil in background
echo "📡 Forking Base Sepolia..."
anvil --fork-url "$BASE_SEPOLIA_RPC" \
      --port $ANVIL_PORT \
      --host 0.0.0.0 \
      --silent &

ANVIL_PID=$!
echo "✅ Anvil started (PID: $ANVIL_PID)"

# Wait for Anvil to be ready
sleep 3

# Fund test address with ETH for gas
echo "💰 Funding test address with ETH for gas..."
cast rpc anvil_setBalance "$TEST_ADDRESS" 0x56BC75E2D63100000 \
     --rpc-url http://127.0.0.1:$ANVIL_PORT > /dev/null

# Find USDC minter admin
echo "🔍 Finding USDC minter admin..."
MINTER_ADMIN=$(cast call "$USDC_ADDRESS" "minterAdmin()" \
     --rpc-url http://127.0.0.1:$ANVIL_PORT | \
     sed 's/0x000000000000000000000000/0x/')

echo "   Minter admin: $MINTER_ADMIN"

# Get minter role
echo "🔍 Getting minter role..."
MINTER_ROLE=$(cast call "$USDC_ADDRESS" "MINTER_ROLE()" \
     --rpc-url http://127.0.0.1:$ANVIL_PORT)

echo "   Minter role: $MINTER_ROLE"

# Get a minter (first one)
echo "🔍 Getting minter address..."
MINTER=$(cast call "$USDC_ADDRESS" "getRoleMember(bytes32,uint256)" \
     "$MINTER_ROLE" 0 \
     --rpc-url http://127.0.0.1:$ANVIL_PORT | \
     sed 's/0x000000000000000000000000/0x/')

echo "   Minter: $MINTER"

# Impersonate the minter
echo "🎭 Impersonating minter..."
cast rpc anvil_impersonateAccount "$MINTER" \
     --rpc-url http://127.0.0.1:$ANVIL_PORT > /dev/null

# Mint 1000 USDC (6 decimals) to test address
MINT_AMOUNT="1000000000"  # 1000 USDC
echo "💸 Minting $MINT_AMOUNT USDC (1000 USDC) to $TEST_ADDRESS..."

cast send "$USDC_ADDRESS" \
     "mint(address,uint256)" \
     "$TEST_ADDRESS" \
     "$MINT_AMOUNT" \
     --from "$MINTER" \
     --rpc-url http://127.0.0.1:$ANVIL_PORT \
     --unlocked > /dev/null

# Check balance
echo "✅ Checking USDC balance..."
BALANCE=$(cast call "$USDC_ADDRESS" "balanceOf(address)(uint256)" \
     "$TEST_ADDRESS" \
     --rpc-url http://127.0.0.1:$ANVIL_PORT)

BALANCE_DEC=$((16#${BALANCE#0x}))
BALANCE_USDC=$(echo "scale=6; $BALANCE_DEC / 1000000" | bc)

echo "   Balance: $BALANCE_USDC USDC"

echo ""
echo "✅ Base Sepolia fork ready!"
echo ""
echo "📋 Configuration:"
echo "   RPC URL: http://127.0.0.1:$ANVIL_PORT"
echo "   Chain ID: 84532"
echo "   USDC: $USDC_ADDRESS"
echo "   Test Address: $TEST_ADDRESS"
echo "   Balance: $BALANCE_USDC USDC"
echo ""
echo "⚠️  Anvil is running in background (PID: $ANVIL_PID)"
echo "   To stop: kill $ANVIL_PID"
echo ""
echo "🚀 Ready for testing!"
