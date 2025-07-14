#!/usr/bin/env python3
"""
Debug PQ Recovery on OP Sepolia
Test the actual contract recovery with test vector data
"""

import json
import sys
from pathlib import Path
from web3 import Web3
from eth_account import Account

# Configuration
OP_SEPOLIA_RPC = "https://sepolia.optimism.io"
CONTRACT_ADDRESS = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"  # Update with actual address

# Contract ABI for confirmRegistration function
CONTRACT_ABI = [
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

def load_test_vector():
    """Load the test vector data for alice"""
    vector_file = Path("test/test_vectors/register/registration_confirmation_vectors.json")
    with open(vector_file, 'r') as f:
        data = json.load(f)
    
    # Get alice's confirmation data
    alice_data = data["registration_confirmation"][0]
    return alice_data

def debug_pq_recovery():
    """Test PQ recovery on OP Sepolia"""
    print("🔍 Debugging PQ Recovery on OP Sepolia")
    print("=" * 50)
    
    # Load test vector
    test_data = load_test_vector()
    
    print(f"📋 Test Data:")
    print(f"  ETH Address: {test_data['eth_address']}")
    print(f"  Expected PQ Fingerprint: {test_data['pq_fingerprint']}")
    print(f"  Actor: {test_data['actor']}")
    
    # Parse signature components
    pq_message = bytes.fromhex(test_data["pq_message"])
    salt = bytes.fromhex(test_data["pq_signature"]["salt"])
    cs1 = [int(x, 16) for x in test_data["pq_signature"]["cs1"]]
    cs2 = [int(x, 16) for x in test_data["pq_signature"]["cs2"]]
    hint = test_data["pq_signature"]["hint"]
    
    print(f"\n📦 Signature Components:")
    print(f"  PQ Message length: {len(pq_message)} bytes")
    print(f"  Salt length: {len(salt)} bytes")
    print(f"  CS1 length: {len(cs1)} elements")
    print(f"  CS2 length: {len(cs2)} elements")
    print(f"  Hint: {hint}")
    
    # Connect to OP Sepolia
    w3 = Web3(Web3.HTTPProvider(OP_SEPOLIA_RPC))
    if not w3.is_connected():
        print("❌ Failed to connect to OP Sepolia")
        return
    
    print(f"\n🌐 Connected to OP Sepolia")
    print(f"  Chain ID: {w3.eth.chain_id}")
    print(f"  Latest block: {w3.eth.block_number}")
    
    # Create contract instance
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    
    print(f"\n📄 Contract Address: {CONTRACT_ADDRESS}")
    
    # Create a test account (we'll use a dummy account since we're just testing)
    test_account = Account.create()
    
    # Build transaction (this will fail, but we can see the revert reason)
    try:
        # Use eth_call to simulate the transaction without requiring gas
        call_data = contract.functions.confirmRegistration(
            pq_message,
            salt,
            cs1,
            cs2,
            hint
        ).encode_input()
        
        print(f"\n✅ Call data encoded successfully")
        print(f"  Call data length: {len(call_data)} bytes")
        
        # Use eth_call to simulate the transaction
        print(f"\n🔄 Attempting to call confirmRegistration...")
        
        # Use eth_call with proper parameters
        result = w3.eth.call({
            'to': CONTRACT_ADDRESS,
            'data': call_data,
            'from': test_account.address,
            'gas': 5000000
        })
        print(f"✅ Call succeeded! Result: {result.hex()}")
        
    except Exception as e:
        print(f"\n❌ Call failed with error: {str(e)}")
        
        # Try to extract more detailed error information
        if "revert" in str(e).lower():
            print(f"🔍 This is a revert - the contract rejected the call")
            print(f"   This could be due to:")
            print(f"   - Invalid PQ signature")
            print(f"   - Wrong fingerprint recovered")
            print(f"   - Message format issues")
            print(f"   - Nonce mismatches")
        
        # Let's also try to decode the error if possible
        try:
            # Try to get more detailed error info
            error_msg = str(e)
            if "0x" in error_msg:
                # Try to decode the error data
                error_data = error_msg.split("0x")[-1]
                print(f"🔍 Error data: 0x{error_data}")
        except:
            pass

if __name__ == "__main__":
    debug_pq_recovery() 