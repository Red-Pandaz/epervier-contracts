#!/usr/bin/env python3
import json
from eth_account import Account
import secrets

def verify_private_key_to_address(private_key_hex, expected_address):
    """Verify that a private key recovers to the expected address."""
    # Remove 0x prefix if present
    if private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]
    
    try:
        # Create account from private key
        account = Account.from_key(private_key_hex)
        recovered_address = account.address
        
        # Compare addresses (case-insensitive)
        matches = recovered_address.lower() == expected_address.lower()
        
        return {
            'private_key': f"0x{private_key_hex}",
            'expected_address': expected_address,
            'recovered_address': recovered_address,
            'matches': matches
        }
    except Exception as e:
        return {
            'private_key': f"0x{private_key_hex}",
            'expected_address': expected_address,
            'error': str(e),
            'matches': False
        }

def main():
    # Load actor config
    with open('test/test_keys/actors_config.json', 'r') as f:
        config = json.load(f)
    
    print("Verifying private key to address mappings:\n")
    
    all_valid = True
    
    for actor_name, actor_data in config['actors'].items():
        private_key = actor_data['eth_private_key']
        expected_address = actor_data['eth_address']
        
        result = verify_private_key_to_address(private_key, expected_address)
        
        print(f"{actor_name.upper()}:")
        print(f"  Private Key: {result['private_key'][:20]}...")
        print(f"  Expected:     {result['expected_address']}")
        
        if 'error' in result:
            print(f"  ERROR:       {result['error']}")
            all_valid = False
        else:
            print(f"  Recovered:   {result['recovered_address']}")
            if result['matches']:
                print(f"  ✅ MATCHES")
            else:
                print(f"  ❌ MISMATCH")
                all_valid = False
        
        print()
    
    if all_valid:
        print("🎉 All private keys correctly recover to their expected addresses!")
    else:
        print("❌ Some private keys do not match their expected addresses.")
    
    return all_valid

if __name__ == "__main__":
    main() 