#!/usr/bin/env python3
"""
Test PQ Registration Intent on local Anvil devnet using generated test vectors.
"""

import json
import sys
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_utils import to_checksum_address
import time

# Contract addresses from the new deployment
REGISTRY_CONTRACT_ADDRESS = "0x99bbA657f2BbC93c02D617f8bA121cB8Fc104Acf"
NFT_CONTRACT_ADDRESS = "0x67d269191c92Caf3cD7723F116c85e6E9bf55933"
EPERVIER_VERIFIER_ADDRESS = "0xc6e7DF5E7b4f2A278906862b61205850344D4e7d"

# Configuration
RPC_URL = "http://localhost:8545"
ANVIL_CHAIN_ID = 31337
TEST_VECTORS_PATH = Path(__file__).parent.parent / "test/test_vectors/devnet/devnet_registration_vectors.json"

# Bob's account (second Anvil account)
BOB_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
BOB_ACCOUNT = Account.from_key(BOB_PRIVATE_KEY)

def load_test_vectors():
    """Load the generated test vectors from devnet directory"""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    test_vectors_file = project_root / "test" / "test_vectors" / "devnet" / "devnet_registration_vectors.json"
    
    if not test_vectors_file.exists():
        print(f"❌ Test vectors file not found: {test_vectors_file}")
        print("Please run the vector generator first:")
        print("python test/python/vector_generators/devnet/generate_registration_vectors.py")
        sys.exit(1)
    
    with open(test_vectors_file, 'r') as f:
        data = json.load(f)
    
    return data

def test_registration_with_real_vectors():
    """Test PQ registration using real generated test vectors"""
    print("🦅 Testing PQ Registration with Real Generated Test Vectors")
    print("=" * 60)
    
    # Load test vectors
    test_data = load_test_vectors()
    test_vector = test_data["registration_intent"]["bob"]  # Get Bob's test vector
    
    print(f"✅ Loaded test vector for: {test_vector['actor']}")
    print(f"✅ ETH Address: {test_vector['eth_address']}")
    print(f"✅ Base PQ Message: {len(bytes.fromhex(test_vector['base_pq_message']))} bytes")
    print(f"✅ ETH Message: {len(bytes.fromhex(test_vector['eth_message']))} bytes")
    print(f"✅ CS1 Array: {len(test_vector['pq_signature']['cs1'])} elements")
    print(f"✅ CS2 Array: {len(test_vector['pq_signature']['cs2'])} elements")
    
    # Setup Web3
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    if not w3.is_connected():
        print("❌ Cannot connect to Anvil. Is it running on localhost:8545?")
        sys.exit(1)
    
    print(f"✅ Connected to Anvil (Chain ID: {w3.eth.chain_id})")
    
    # Use Bob's private key (second Anvil account)
    bob_private_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    account = Account.from_key(bob_private_key)
    balance = w3.eth.get_balance(account.address)
    print(f"✅ Account balance: {w3.from_wei(balance, 'ether')} ETH")
    
    if balance == 0:
        print("❌ Account has no ETH. Please fund it first.")
        sys.exit(1)
    
    # Prepare contract call data
    eth_message_bytes = bytes.fromhex(test_vector['eth_message'])
    
    # Extract signature components
    v_raw = test_vector['eth_signature']['v']
    r = bytes.fromhex(test_vector['eth_signature']['r'][2:])  # Remove 0x prefix
    s = bytes.fromhex(test_vector['eth_signature']['s'][2:])  # Remove 0x prefix
    
    # Use the v value as-is from the vector (already correct for EIP-712)
    v = v_raw
    
    print(f"✅ Prepared contract call data:")
    print(f"   - ETH message: {len(eth_message_bytes)} bytes")
    print(f"   - ETH signature: v={v} (raw={v_raw}), r={r.hex()[:16]}..., s={s.hex()[:16]}...")
    
    # Contract ABI for submitRegistrationIntent (correct signature)
    registry_abi = [
        {
            "inputs": [
                {"name": "ethMessage", "type": "bytes"},
                {"name": "v", "type": "uint8"},
                {"name": "r", "type": "bytes32"},
                {"name": "s", "type": "bytes32"}
            ],
            "name": "submitRegistrationIntent",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    
    # Create contract instance
    registry = w3.eth.contract(
        address=REGISTRY_CONTRACT_ADDRESS,
        abi=registry_abi
    )
    
    # Submit registration intent
    print("\n🚀 Submitting registration intent to contract...")
    print("-" * 40)
    
    try:
        # Build transaction with higher gas limit for PQ verification
        tx = registry.functions.submitRegistrationIntent(
            eth_message_bytes,
            v,
            r,
            s
        ).build_transaction({
            'from': account.address,
            'gas': 30000000,  # Increased gas limit for PQ verification
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account.address)
        })
        
        # Sign and send transaction
        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        print(f"✅ Transaction submitted: {tx_hash.hex()}")
        print("⏳ Waiting for transaction receipt...")
        
        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        
        if receipt.status == 1:
            print("\n🎉 SUCCESS! Registration completed successfully!")
            print(f"✅ Gas used: {receipt.gasUsed:,}")
            print(f"✅ Block number: {receipt.blockNumber}")
            print(f"✅ Transaction hash: {receipt.transactionHash.hex()}")
            
            # Check if NFT was minted (if registry auto-mints)
            if len(receipt.logs) > 0:
                print(f"✅ Events emitted: {len(receipt.logs)}")
            
            return True
        else:
            print("❌ Transaction failed")
            print(f"❌ Gas used: {receipt.gasUsed:,}")
            print(f"❌ Block number: {receipt.blockNumber}")
            
            # Try to get revert reason
            try:
                # Replay the transaction to get revert reason
                w3.eth.call({
                    'from': account.address,
                    'to': REGISTRY_CONTRACT_ADDRESS,
                    'data': tx['data'],
                    'gas': tx['gas'],
                    'gasPrice': tx['gasPrice']
                }, receipt.blockNumber)
            except Exception as e:
                print(f"❌ Revert reason: {e}")
            
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Main test function"""
    print("🦅 EPERVIER DEVNET TEST SUITE")
    print("Testing with real ETHFALCON signatures generated locally")
    print("=" * 60)
    
    try:
        success = test_registration_with_real_vectors()
        
        if success:
            print("\n✅ ALL TESTS PASSED!")
            print("🎉 Real ETHFALCON signatures work with local contracts!")
        else:
            print("\n❌ TEST FAILED!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n👋 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 