#!/usr/bin/env python3

import json
import sys
import os
from web3 import Web3
from eth_account import Account
import time
import binascii

# Add the current directory to the path to import eip712_helpers
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def load_config():
    """Load devnet configuration"""
    config_path = "test/python/devnet_config.json"
    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        return None
    
    with open(config_path, 'r') as f:
        return json.load(f)

def load_vectors():
    """Load production token transfer vectors"""
    vectors_path = "test/test_vectors/production/transfer/pq_transfer_vectors.json"
    if not os.path.exists(vectors_path):
        print(f"❌ Vectors file not found: {vectors_path}")
        return None
    
    with open(vectors_path, 'r') as f:
        return json.load(f)

def test_token_transfer(config, vector):
    """Test a single token transfer vector"""
    try:
        # Connect to devnet
        w3 = Web3(Web3.HTTPProvider(config['rpc_url']))
        
        # Load contract ABI and address
        contract_address = Web3.to_checksum_address(config['pq_registry_address'])
        
        # Load the contract ABI from the compiled contract
        abi_path = "out/PQRegistry.sol/PQRegistry.json"
        with open(abi_path, 'r') as f:
            contract_data = json.load(f)
            abi = contract_data['abi']
        
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Prepare the transfer parameters
        pq_message = bytes.fromhex(vector['pq_message'])
        salt = bytes.fromhex(vector['pq_signature']['salt'])
        hint = vector['pq_signature']['hint']
        cs1 = [int(x, 16) for x in vector['pq_signature']['cs1']]
        cs2 = [int(x, 16) for x in vector['pq_signature']['cs2']]
        
        # Build the transaction
        deployer_address = Web3.to_checksum_address(config['deployer_address'])
        tx = contract.functions.transferTokenWithPQSignature(
            vector['token_id'],
            vector['to_address'],
            pq_message,
            salt,
            cs1,
            cs2,
            hint
        ).build_transaction({
            'from': deployer_address,
            'gas': 5000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(deployer_address)
        })
        
        # Sign and send the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, config['deployer_private_key'])
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print(f"✅ Token transfer successful: {vector['description']}")
            print(f"   Transaction hash: {tx_hash.hex()}")
            print(f"   Gas used: {receipt.gasUsed}")
            return True
        else:
            print(f"❌ Token transfer failed: {vector['description']}")
            print(f"   Transaction hash: {tx_hash.hex()}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing token transfer: {vector['description']}")
        print(f"   Error: {str(e)}")
        return False

def main():
    """Main function to test all token transfer vectors"""
    print("🚀 Starting token transfer tests on devnet...")
    
    # Load configuration
    config = load_config()
    if not config:
        return
    
    # Load vectors
    vectors_data = load_vectors()
    if not vectors_data:
        return
    
    vectors = vectors_data.get('pq_transfers', [])
    if not vectors:
        print("❌ No token transfer vectors found")
        return
    
    print(f"📋 Found {len(vectors)} token transfer vectors to test")
    
    # Test each vector
    success_count = 0
    total_count = len(vectors)
    
    for i, vector in enumerate(vectors, 1):
        print(f"\n📝 Testing vector {i}/{total_count}: {vector['description']}")
        print(f"   From: {vector['from_fingerprint']}")
        print(f"   To: {vector['to_address']}")
        print(f"   Token ID: {vector['token_id']}")
        print(f"   Expected result: {vector['expected_result']}")
        
        if test_token_transfer(config, vector):
            success_count += 1
        
        # Add a small delay between transactions
        time.sleep(2)
    
    # Print summary
    print(f"\n📊 Test Summary:")
    print(f"   Total vectors tested: {total_count}")
    print(f"   Successful transfers: {success_count}")
    print(f"   Failed transfers: {total_count - success_count}")
    
    if success_count == total_count:
        print("🎉 All token transfers successful!")
    else:
        print("⚠️  Some token transfers failed")

if __name__ == "__main__":
    main() 