# OP Sepolia Deployment Guide

This guide explains how to deploy the PQ Registry and PQERC721 contracts to OP Sepolia.

## Prerequisites

1. **Private Key**: Your deployment wallet private key
2. **Etherscan API Key**: For contract verification
3. **Forge**: Make sure you have Foundry installed

## Environment Setup

Set the following environment variables:

```bash
# Required
export PRIVATE_KEY=your_private_key_here

# Optional (will use defaults if not set)
export RPC_URL=https://sepolia.optimism.io
export ETHERSCAN_API_KEY=your_etherscan_api_key_here
```

## Deployment

### Option 1: Using the shell script (Recommended)

```bash
./script/deploy_op_sepolia.sh
```

### Option 2: Manual deployment

```bash
forge script script/DeployOPSepolia.s.sol:DeployOPSepolia \
    --rpc-url https://sepolia.optimism.io \
    --broadcast \
    --verify \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verifier-url https://api-sepolia-optimistic.etherscan.io/api
```

## What Gets Deployed

1. **PQRegistry**: The main registry contract for managing PQ fingerprint registrations
2. **PQERC721**: The NFT contract for PQ-based token transfers

## Contract Initialization

The deployment script automatically:

1. Deploys both contracts
2. Initializes the NFT contract with the registry address
3. Registers the NFT contract with the registry
4. Displays all contract addresses and domain separators

## Configuration

- **Epervier Verifier**: `0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B` (OP Sepolia)
- **Chain ID**: 11155420 (OP Sepolia)
- **Network**: Optimism Sepolia

## Verification

After deployment, you can verify the contracts on:
- **Optimistic Etherscan**: https://sepolia-optimistic.etherscan.io/

## Domain Separators

The contracts use EIP-712 domain separators that include:
- Contract name and version
- Chain ID (11155420 for OP Sepolia)
- Contract address (unique per deployment)

This ensures signatures are chain-specific and contract-specific.

## Testing After Deployment

You can test the deployed contracts using the test vectors and scripts in the `test/` directory. 