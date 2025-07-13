# Production Vector Generation

This directory contains vector generators for the production contracts (PQRegistry.sol and PQERC721.sol) that will be deployed on OP Sepolia.

## Overview

The production contracts use **dynamic domain separators** that are calculated at deployment time, unlike the Test contracts which use hardcoded domain separators. This means we need to:

1. Deploy the production contracts first
2. Extract the actual domain separators from the deployed contracts
3. Generate vectors using those domain separators

## Files

- `production_registration_intent_generator.py` - Generates registration intent vectors
- `production_registration_confirmation_generator.py` - Generates registration confirmation vectors  
- `production_pq_transfer_generator.py` - Generates PQ transfer vectors
- `README.md` - This file

## Actors

The production vectors use a separate actor configuration (`test/test_keys/production_actors_config.json`) with new ETH addresses and keypairs:

- **Kyle**: `0x46649c007Edff0a0a4a05b6776d3acf4a17A108A`
- **Luke**: `0x9e55891A8EF43E27081371542B2b3db7fe0E8B2B`
- **Marie**: `0xA860D80B8cbC082F29433DDB0E549850ed961071`
- **Nancy**: `0x79076844674AdA9Abe7d74Dd9Ab733407d1A0556`
- **Oscar**: `0x9a8a95D9590F523a9DA97a69B3bCeBfD51Fd0135`

## Usage

### Step 1: Deploy Production Contracts

```bash
# Deploy the production contracts to get domain separators
python3 scripts/deploy_and_generate_production_vectors.py
```

This script will:
1. Deploy PQRegistry.sol and PQERC721.sol
2. Extract the domain separators from the deployed contracts
3. Update the vector generators with the correct domain separators
4. Generate all production vectors

### Step 2: Generate Vectors Manually (if needed)

```bash
# Generate registration intent vectors
python3 test/python/vector_generators/dev/production_registration_intent_generator.py

# Generate registration confirmation vectors  
python3 test/python/vector_generators/dev/production_registration_confirmation_generator.py

# Generate PQ transfer vectors
python3 test/python/vector_generators/dev/production_pq_transfer_generator.py
```

## Output

The vectors are saved to `test/test_vectors/dev/`:

- `registration_intent_vectors.json` - Registration intent vectors
- `registration_confirmation_vectors.json` - Registration confirmation vectors
- `pq_transfer_vectors.json` - PQ transfer vectors
- `contract_info.json` - Contract addresses and domain separators

## Security

⚠️ **IMPORTANT**: The production actor config contains real private keys and is gitignored. Never commit these keys to version control!

The following files are gitignored:
- `test/test_keys/production_actors_config.json`
- `test/test_keys/prod_private_key_*.pem`
- `test/test_keys/prod_public_key_*.pem`
- `test/test_vectors/dev/`

## Differences from Test Vectors

1. **Dynamic Domain Separators**: Production contracts calculate domain separators at deployment time
2. **New Actors**: Uses Kyle, Luke, Marie, Nancy, Oscar instead of Alice, Bob, Charlie
3. **Real Addresses**: Uses real ETH addresses instead of Anvil's default addresses
4. **Production Contracts**: Uses PQRegistry.sol and PQERC721.sol instead of Test versions

## Testing on OP Sepolia

These vectors are designed to be tested on OP Sepolia with the deployed production contracts. The domain separators will match the actual deployed contracts. 