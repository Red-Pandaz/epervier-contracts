#!/usr/bin/env python3

import json
import sys
import os
from web3 import Web3
from eth_account import Account
import time
import binascii

# Use the config file as before
CONFIG_PATH = "production_config.json"

# Add the current directory to the path to import eip712_helpers
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def load_config():
    """Load configuration from config file"""
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

config = load_config()
RPC_URL = config['rpc_url']
DEPLOYER_ADDRESS = config['deployer_address']
DEPLOYER_PRIVATE_KEY = config['deployer_private_key']
PQ_REGISTRY_ADDRESS = config['pq_registry_address']
DOMAIN_SEPARATOR = config['domain_separator']

def load_vectors():
    """Load production registration confirmation vectors"""
    vectors_path = "../test_vectors/production/register/registration_confirmation_vectors.json"
    if not os.path.exists(vectors_path):
        print(f"❌ Vectors file not found: {vectors_path}")
        return None
    
    with open(vectors_path, 'r') as f:
        data = json.load(f)
        return data.get('registration_confirmation', [])

def test_registration_confirmation(w3, config, vector):
    """Test a single registration confirmation vector"""
    try:
        actor_name = vector.get('actor', 'unknown')
        eth_address = vector.get('eth_address', '')
        
        print(f"\n🔍 Testing {actor_name} ({eth_address})")
        
        # Extract the PQ message and signature components from the vector
        pq_message = bytes.fromhex(vector['pq_message'])
        pq_signature = vector['pq_signature']
        cs1 = [int(x, 16) for x in pq_signature['cs1']]
        cs2 = [int(x, 16) for x in pq_signature['cs2']]
        salt = bytes.fromhex(pq_signature['salt'])
        hint = int(pq_signature['hint'])
        # Convert to uint256 (no masking needed)
        
        print(f"✅ Extracted PQ message: {len(pq_message)} bytes")
        print(f"✅ Extracted signature: cs1={len(cs1)} values, cs2={len(cs2)} values")
        print(f"✅ Extracted salt: {len(salt)} bytes, hint: {hint}")
        
        # Prepare transaction (always from deployer)
        deployer_address = Web3.to_checksum_address(config['deployer_address'])
        # Contract address from devnet deployment
        registry_address = Web3.to_checksum_address(config['pq_registry_address'])
        
        # Create contract instance with ABI
        # PQRegistry ABI for confirmRegistration function
        abi = [
            {
                "inputs": [
                    {"internalType": "bytes", "name": "pqMessage", "type": "bytes"},
                    {"internalType": "bytes", "name": "salt", "type": "bytes"},
                    {"internalType": "uint256[]", "name": "cs1", "type": "uint256[]"},
                    {"internalType": "uint256[]", "name": "cs2", "type": "uint256[]"},
                    {"internalType": "uint256", "name": "hint", "type": "uint256"}
                ],
                "name": "confirmRegistration",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        contract = w3.eth.contract(address=registry_address, abi=abi)
        
        # Call the function directly like the Solidity script does
        print(f"✅ Calling confirmRegistration directly...")
        
        # Prepare transaction
        tx = contract.functions.confirmRegistration(
            pq_message, salt, cs1, cs2, hint
        ).build_transaction({
            'from': deployer_address,
            'gas': 30000000,  # High gas limit for complex operation
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(deployer_address)
        })
        
        # Sign and send transaction as deployer
        signed_tx = w3.eth.account.sign_transaction(tx, config['deployer_private_key'])
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        print(f"📤 Transaction sent: {tx_hash.hex()}")
        
        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] == 1:
            print(f"✅ Registration confirmation successful for {actor_name}")
            print(f"   Gas used: {receipt['gasUsed']:,}")
            return True
        else:
            print(f"❌ Registration confirmation failed for {actor_name}")
            # Get the revert reason from the transaction receipt
            try:
                # Try to get the revert reason from the transaction
                tx = w3.eth.get_transaction(tx_hash)
                # Replay the transaction to get the revert reason
                result = w3.eth.call(tx, receipt['blockNumber'] - 1)
                print(f"   Unexpected: call succeeded but transaction failed")
            except Exception as call_error:
                # Extract the revert reason from the error
                error_str = str(call_error)
                if "execution reverted" in error_str:
                    # Try to extract the custom error message
                    if ":" in error_str:
                        revert_reason = error_str.split(":")[-1].strip()
                        print(f"   Revert reason: {revert_reason}")
                    else:
                        print(f"   Revert reason: {error_str}")
                else:
                    print(f"   Error: {error_str}")
            return False
            
    except Exception as e:
        print(f"❌ Registration confirmation failed for {actor_name}: {e}")
        return False

def main():
    print("🚀 Testing Production Registration Confirmation Vectors")
    print("=" * 60)
    
    # Load configuration
    config = load_config()
    if not config:
        return
    
    # Connect to devnet
    w3 = Web3(Web3.HTTPProvider(config['rpc_url']))
    if not w3.is_connected():
        print("❌ Failed to connect to devnet")
        return
    
    print(f"✅ Connected to devnet at {config['rpc_url']}")
    
    # Load vectors
    vectors = load_vectors()
    if not vectors:
        return
    
    print(f"📋 Loaded {len(vectors)} registration confirmation vectors")
    
    # Test each vector
    print(f"\n📊 Progress: 0/{len(vectors)}")
    success_count = 0
    
    for i, vector in enumerate(vectors, 1):
        print(f"\n📊 Progress: {i}/{len(vectors)}")
        if test_registration_confirmation(w3, config, vector):
            success_count += 1
    
    print(f"\n🎯 Results: {success_count}/{len(vectors)} successful")
    print(f"📈 Success Rate: {success_count/len(vectors)*100:.1f}%")

if __name__ == "__main__":
    main() 