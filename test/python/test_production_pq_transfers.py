#!/usr/bin/env python3

import json
import sys
import os
from web3 import Web3
from eth_account import Account
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def load_config():
    """Load production configuration"""
    config_path = "production_config.json"
    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        return None
    
    with open(config_path, 'r') as f:
        return json.load(f)

def load_vectors():
    """Load production PQ transfer vectors"""
    vectors_path = "../test_vectors/production/transfer/pq_transfer_vectors.json"
    if not os.path.exists(vectors_path):
        print(f"❌ Vectors file not found: {vectors_path}")
        return None
    
    with open(vectors_path, 'r') as f:
        return json.load(f)

def test_pq_transfer(config, vector):
    """Test a single PQ transfer vector"""
    try:
        # Connect to OP Sepolia
        w3 = Web3(Web3.HTTPProvider('https://sepolia.optimism.io'))
        
        # PQERC721 contract address
        contract_address = Web3.to_checksum_address('0x9f6A2b8560FceF521ACe81c651CFd8A07381B950')
        
        # PQERC721 ABI for pqTransferFrom function
        abi = [
            {
                "inputs": [
                    {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "bytes", "name": "pqMessage", "type": "bytes"},
                    {"internalType": "bytes", "name": "salt", "type": "bytes"},
                    {"internalType": "uint256[]", "name": "cs1", "type": "uint256[]"},
                    {"internalType": "uint256[]", "name": "cs2", "type": "uint256[]"},
                    {"internalType": "uint256", "name": "hint", "type": "uint256"}
                ],
                "name": "pqTransferFrom",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Extract the PQ message and signature components from the vector
        pq_message = bytes.fromhex(vector['pq_message'])
        pq_signature = vector['pq_signature']
        
        # Handle both hex strings and integers in cs1/cs2
        def parse_cs_values(cs_list):
            parsed = []
            for x in cs_list:
                if isinstance(x, str):
                    if x.startswith('0x'):
                        parsed.append(int(x, 16))
                    else:
                        parsed.append(int(x, 16))
                else:
                    parsed.append(int(x))
            return parsed
        
        cs1 = parse_cs_values(pq_signature['cs1'])
        cs2 = parse_cs_values(pq_signature['cs2'])
        
        # Handle salt format (could be hex string or bytes)
        salt_data = pq_signature['salt']
        if isinstance(salt_data, str):
            if salt_data.startswith('0x'):
                salt = bytes.fromhex(salt_data[2:])
            else:
                salt = bytes.fromhex(salt_data)
        else:
            salt = salt_data
            
        hint = pq_signature['hint']
        
        print(f"✅ Extracted PQ message: {len(pq_message)} bytes")
        print(f"✅ Extracted signature: cs1={len(cs1)} values, cs2={len(cs2)} values")
        print(f"✅ Extracted salt: {len(salt)} bytes, hint: {hint}")
        
        # Create contract instance with ABI
        # PQERC721 ABI for pqTransferFrom function
        abi = [
            {
                "inputs": [
                    {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "bytes", "name": "pqMessage", "type": "bytes"},
                    {"internalType": "bytes", "name": "salt", "type": "bytes"},
                    {"internalType": "uint256[]", "name": "cs1", "type": "uint256[]"},
                    {"internalType": "uint256[]", "name": "cs2", "type": "uint256[]"},
                    {"internalType": "uint256", "name": "hint", "type": "uint256"}
                ],
                "name": "pqTransferFrom",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Call the function directly like the confirmation test
        deployer_address = Web3.to_checksum_address(config['deployer_address'])
        deployer_private_key = config['deployer_private_key']
        
        # Build the transaction
        tx = contract.functions.pqTransferFrom(
            vector['token_id'],
            Web3.to_checksum_address(vector['to_address']),
            pq_message,
            salt,
            cs1,
            cs2,
            hint
        ).build_transaction({
            'from': deployer_address,
            'gas': 15000000,  # 15M gas for PQ operations
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(deployer_address)
        })
        
        # Sign and send the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, deployer_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print(f"✅ PQ transfer successful: {vector['description']}")
            print(f"   Transaction hash: {tx_hash.hex()}")
            print(f"   Gas used: {receipt.gasUsed}")
            return True
        else:
            print(f"❌ PQ transfer failed: {vector['description']}")
            print(f"   Transaction hash: {tx_hash.hex()}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing PQ transfer: {vector['description']}")
        print(f"   Error: {str(e)}")
        return False

def main():
    """Main function to test all PQ transfer vectors"""
    print("🚀 Starting PQ transfer tests on OP Sepolia...")
    
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
        print("❌ No PQ transfer vectors found")
        return
    
    print(f"📋 Found {len(vectors)} PQ transfer vectors to test")
    
    # Test each vector
    success_count = 0
    total_count = len(vectors)
    
    for i, vector in enumerate(vectors, 1):
        print(f"\n📝 Testing vector {i}/{total_count}: {vector['description']}")
        print(f"   From: {vector['from_fingerprint']}")
        print(f"   To: {vector['to_address']}")
        print(f"   Token ID: {vector['token_id']}")
        print(f"   Expected result: {vector['expected_result']}")
        
        if test_pq_transfer(config, vector):
            success_count += 1
        
        # Add a small delay between transactions
        time.sleep(2)
    
    # Print summary
    print(f"\n📊 Test Summary:")
    print(f"   Total vectors tested: {total_count}")
    print(f"   Successful transfers: {success_count}")
    print(f"   Failed transfers: {total_count - success_count}")
    print(f"   Success rate: {(success_count/total_count)*100:.1f}%")
    
    if success_count == total_count:
        print("🎉 All PQ transfers successful!")
    else:
        print("⚠️  Some PQ transfers failed")

if __name__ == "__main__":
    main() 