#!/usr/bin/env python3
"""
Test Production Registration Intent Vectors against local Anvil devnet.
"""

import json
import sys
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_utils import to_checksum_address
import time

# Contract addresses from the new devnet deployment
REGISTRY_CONTRACT_ADDRESS = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
NFT_CONTRACT_ADDRESS = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
EPERVIER_VERIFIER_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

# Configuration
RPC_URL = "http://localhost:8545"
ANVIL_CHAIN_ID = 31337
PRODUCTION_VECTORS_PATH = Path(__file__).parent.parent / "test/test_vectors/production/register/registration_intent_vectors.json"

# Production actor private keys (from production_actors_config.json)
PRODUCTION_PRIVATE_KEYS = {
    "kyle": "0x8f96585605ecda461b8783412e39055a9a5ceded23be6e7b113b25e7d90362c8",
    "luke": "0x39fe7b01bdf6c46b044d82c0d327caaecebfdc07d91971eb40bed023c9c594de", 
    "marie": "0x702788f19d9c834e0c2173daba13fd1816577b1101d375f4ad9d9d91974f2454",
    "nancy": "0x552833285f3840290eba3af4c6972f15d106ea3428893a9caaceb4c481453859",
    "oscar": "0xb4122b40585fca51de429efe0ff093e334e00ff992df12857e1f63a17faa9f69"
}

def load_production_vectors():
    """Load the production registration intent vectors"""
    if not PRODUCTION_VECTORS_PATH.exists():
        print(f"❌ Production vectors file not found: {PRODUCTION_VECTORS_PATH}")
        print("Please run the production vector generator first:")
        print("python test/python/vector_generators/production/generate_production_vectors.py")
        sys.exit(1)
    
    with open(PRODUCTION_VECTORS_PATH, 'r') as f:
        data = json.load(f)
    
    return data

def test_production_registration_intent(actor_name, test_vector):
    """Test a single production registration intent vector"""
    print(f"\n🦅 Testing Production Registration Intent for {actor_name.upper()}")
    print("-" * 60)
    
    print(f"✅ Actor: {actor_name}")
    print(f"✅ ETH Address: {test_vector['eth_address']}")
    print(f"✅ PQ Fingerprint: {test_vector['pq_fingerprint']}")
    print(f"✅ Base PQ Message: {len(bytes.fromhex(test_vector['base_pq_message']))} bytes")
    print(f"✅ ETH Message: {len(bytes.fromhex(test_vector['eth_message']))} bytes")
    print(f"✅ ETH Nonce: {test_vector['eth_nonce']}")
    
    # Setup Web3
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    if not w3.is_connected():
        print("❌ Cannot connect to Anvil. Is it running on localhost:8545?")
        return False
    
    print(f"✅ Connected to Anvil (Chain ID: {w3.eth.chain_id})")
    
    # Use the actor's private key
    if actor_name not in PRODUCTION_PRIVATE_KEYS:
        print(f"❌ No private key found for actor: {actor_name}")
        return False
    
    private_key = PRODUCTION_PRIVATE_KEYS[actor_name]
    account = Account.from_key(private_key)
    balance = w3.eth.get_balance(account.address)
    print(f"✅ Account balance: {w3.from_wei(balance, 'ether')} ETH")
    
    if balance == 0:
        print("❌ Account has no ETH. Please fund it first.")
        return False
    
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
    
    # Contract ABI for submitRegistrationIntent
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
    print(f"\n🚀 Submitting registration intent for {actor_name}...")
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
            print(f"\n🎉 SUCCESS! Registration completed for {actor_name}!")
            print(f"✅ Gas used: {receipt.gasUsed:,}")
            print(f"✅ Block number: {receipt.blockNumber}")
            print(f"✅ Transaction hash: {receipt.transactionHash.hex()}")
            
            # Check if NFT was minted (if registry auto-mints)
            if len(receipt.logs) > 0:
                print(f"✅ Events emitted: {len(receipt.logs)}")
            
            return True
        else:
            print(f"❌ Transaction failed for {actor_name}")
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
        print(f"❌ Error for {actor_name}: {e}")
        return False

def main():
    """Main test function"""
    print("🦅 EPERVIER PRODUCTION REGISTRATION INTENT TEST SUITE")
    print("Testing production vectors against local devnet")
    print("=" * 60)
    
    # Load production vectors
    test_data = load_production_vectors()
    registration_intents = test_data["registration_intent"]
    
    print(f"✅ Loaded {len(registration_intents)} production registration intent vectors")
    
    # Test each production actor
    results = {}
    
    for vector in registration_intents:
        actor = vector['actor']
        print(f"\n{'='*60}")
        print(f"Testing {actor.upper()} registration intent...")
        print(f"{'='*60}")
        
        success = test_production_registration_intent(actor, vector)
        results[actor] = success
        
        # Small delay between tests
        time.sleep(1)
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 PRODUCTION REGISTRATION INTENT TEST RESULTS")
    print(f"{'='*60}")
    
    passed = 0
    total = len(results)
    
    for actor, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{actor.upper():<10} : {status}")
        if success:
            passed += 1
    
    print(f"\n📈 Summary: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 ALL PRODUCTION REGISTRATION INTENT TESTS PASSED!")
        print("✅ Production vectors work correctly with devnet contracts!")
    else:
        print(f"\n❌ {total-passed} tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite error: {e}")
        sys.exit(1) 