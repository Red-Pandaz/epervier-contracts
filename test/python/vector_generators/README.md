# PQRegistry Test Vector Generators

This directory contains Python scripts for generating test vectors for the PQRegistry contract tests.

## Quick Start

To generate all test vectors in one command:

```bash
cd test/python/vector_generators
python3 generate_all_vectors.py
```

## Available Scripts

### Comprehensive Generator
- **`generate_all_vectors.py`** - Generates all test vectors in the correct order

### Individual Generators
- **`registration_intent_generator.py`** - ETH-controlled registration intent messages
- **`registration_confirmation_generator.py`** - PQ-controlled registration confirmation messages
- **`registration_intent_eth_removal_generator.py`** - ETH-controlled registration intent removal
- **`registration_intent_pq_removal_generator.py`** - PQ-controlled registration intent removal
- **`change_eth_address_intent_generator.py`** - PQ-controlled change ETH address intent messages
- **`change_eth_address_confirmation_generator.py`** - ETH-controlled change ETH address confirmation messages
- **`change_eth_address_intent_eth_removal_generator.py`** - ETH-controlled change ETH address intent removal
- **`change_eth_address_intent_pq_removal_generator.py`** - PQ-controlled change ETH address intent removal
- **`unregistration_intent_generator.py`** - PQ-controlled unregistration intent messages
- **`unregistration_confirmation_generator.py`** - ETH-controlled unregistration confirmation messages
- **`unregistration_intent_pq_removal_generator.py`** - PQ-controlled unregistration intent removal

## Usage

### Generate All Vectors
```bash
python3 generate_all_vectors.py
```

### Force Regenerate All Vectors
```bash
python3 generate_all_vectors.py --force
```

### Check Dependencies Only
```bash
python3 generate_all_vectors.py --check-only
```

### Generate for Testing (Subset of Actors)
```bash
python3 generate_all_vectors.py --actors-only
```

## Dependencies

The scripts require:
- Python 3.7+
- `eth_account` library
- `eth_utils` library
- Epervier signing CLI (`ETHFALCON/python-ref/sign_cli.py`)
- Python virtual environment (`ETHFALCON/python-ref/myenv/`)
- Actors configuration (`test/test_keys/actors_config.json`)

## Output

All generated vectors are saved to `test/test_vectors/` with the following files:
- `registration_intent_vectors.json`
- `registration_confirmation_vectors.json`
- `registration_eth_removal_vectors.json`
- `registration_pq_removal_vectors.json`
- `change_eth_address_intent_vectors.json`
- `change_eth_address_confirmation_vectors.json`
- `change_eth_address_cancel_eth_vectors.json`
- `change_eth_address_cancel_pq_vectors.json`
- `unregistration_intent_vectors.json`
- `unregistration_confirmation_vectors.json`
- `unregistration_removal_vectors.json`

## Vector Types

### Registration Flow
1. **Registration Intent** - ETH address initiates registration with PQ key
2. **Registration Confirmation** - PQ key confirms the registration
3. **Registration Removal** - Either party can remove pending registration intent

### Change ETH Address Flow
1. **Change Intent** - PQ key initiates change of bound ETH address
2. **Change Confirmation** - New ETH address confirms the change
3. **Change Removal** - Either party can remove pending change intent

### Unregistration Flow
1. **Unregistration Intent** - PQ key initiates unregistration
2. **Unregistration Confirmation** - ETH address confirms unregistration
3. **Unregistration Removal** - PQ key can remove pending unregistration intent

## Troubleshooting

### Common Issues
1. **Missing dependencies** - Run `python3 generate_all_vectors.py --check-only` to verify
2. **Permission errors** - Ensure the script is executable: `chmod +x generate_all_vectors.py`
3. **Python path issues** - Make sure you're running from the correct directory

### Debugging
- Use `--check-only` to verify all dependencies are available
- Check individual generator scripts for specific error messages
- Verify that the Epervier signing CLI is working correctly 