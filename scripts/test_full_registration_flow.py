#!/usr/bin/env python3
"""
Test the complete PQ registration flow on local Anvil devnet:
1. Registration Intent
2. Registration Confirmation  
3. PQTransferFrom
"""

import json
import sys
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_utils import to_checksum_address
import time

# Contract addresses from the deployment
REGISTRY_CONTRACT_ADDRESS = "0x99bbA657f2BbC93c02D617f8bA121cB8Fc104Acf"
NFT_CONTRACT_ADDRESS = "0x67d269191c92Caf3cD7723F116c85e6E9bf55933" 
EPERVIER_VERIFIER_ADDRESS = "0xc6e7DF5E7b4f2A278906862b61205850344D4e7d"

# Configuration
RPC_URL = "http://localhost:8545"
ANVIL_CHAIN_ID = 31337
TEST_VECTORS_PATH = Path(__file__).parent.parent / "test/test_vectors/devnet/devnet_registration_vectors.json"

# Alice's account (first Anvil account)
ALICE_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ALICE_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

def load_test_vectors():
    """Load test vectors from JSON file."""
    with open(TEST_VECTORS_PATH, 'r') as f:
        return json.load(f)

def test_registration_intent(w3, test_data):
    """Test registration intent submission."""
    print("\n🔥 Testing Registration Intent")
    print("=" * 50)
    
    # Get Alice's intent data
    alice_intent = test_data["registration_intent"]["alice"]
    
    # Prepare transaction data
    eth_message_bytes = bytes.fromhex(alice_intent["eth_message"])
    v = alice_intent["eth_signature"]["v"]
    r = int(alice_intent["eth_signature"]["r"], 16).to_bytes(32, 'big')
    s = int(alice_intent["eth_signature"]["s"], 16).to_bytes(32, 'big')
    
    print(f"📨 ETH Message: {len(eth_message_bytes)} bytes")
    print(f"🖊️  ETH Signature: v={v}, r={r.hex()[:10]}..., s={s.hex()[:10]}...")
    
    # Create contract interface
    registry_abi = [{"inputs":[{"internalType":"bytes","name":"ethMessage","type":"bytes"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"submitRegistrationIntent","outputs":[],"stateMutability":"nonpayable","type":"function"}]
    
    registry = w3.eth.contract(address=to_checksum_address(REGISTRY_CONTRACT_ADDRESS), abi=registry_abi)
    account = Account.from_key(ALICE_PRIVATE_KEY)
    
    # Build transaction with higher gas limit for PQ verification
    tx = registry.functions.submitRegistrationIntent(
        eth_message_bytes,
        v,
        r,
        s
    ).build_transaction({
        'from': account.address,
        'gas': 30000000,  # High gas limit for PQ verification
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address)
    })
    
    # Sign and send transaction
    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"📤 Transaction sent: {tx_hash.hex()}")
    
    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    if receipt.status == 1:
        print(f"✅ Registration intent successful!")
        print(f"   Gas used: {receipt.gasUsed:,}")
        print(f"   Block: {receipt.blockNumber}")
        return True
    else:
        print(f"❌ Registration intent failed!")
        return False

def test_registration_confirmation(w3, test_data):
    """Test registration confirmation."""
    print("\n🔥 Testing Registration Confirmation")
    print("=" * 50)
    
    # Get Alice's confirmation data
    alice_confirmation = test_data["registration_confirmation"]["alice"]
    
    # Prepare transaction data
    pq_message_bytes = bytes.fromhex(alice_confirmation["pq_message"])
    salt_bytes = bytes.fromhex(alice_confirmation["pq_signature"]["salt"])
    cs1 = [int(x, 16) for x in alice_confirmation["pq_signature"]["cs1"]]
    cs2 = [int(x, 16) for x in alice_confirmation["pq_signature"]["cs2"]]
    hint = alice_confirmation["pq_signature"]["hint"]
    
    print(f"📨 PQ Message: {len(pq_message_bytes)} bytes")
    print(f"🖊️  PQ Signature: salt={len(salt_bytes)}B, cs1={len(cs1)} elements, cs2={len(cs2)} elements, hint={hint}")
    
    # Create contract interface
    registry_abi = [{"inputs":[{"internalType":"bytes","name":"pqMessage","type":"bytes"},{"internalType":"bytes","name":"salt","type":"bytes"},{"internalType":"uint256[]","name":"cs1","type":"uint256[]"},{"internalType":"uint256[]","name":"cs2","type":"uint256[]"},{"internalType":"uint256","name":"hint","type":"uint256"}],"name":"confirmRegistration","outputs":[],"stateMutability":"nonpayable","type":"function"}]
    
    registry = w3.eth.contract(address=to_checksum_address(REGISTRY_CONTRACT_ADDRESS), abi=registry_abi)
    account = Account.from_key(ALICE_PRIVATE_KEY)
    
    # Build transaction with higher gas limit for PQ verification
    tx = registry.functions.confirmRegistration(
        pq_message_bytes,
        salt_bytes,
        cs1,
        cs2,
        hint
    ).build_transaction({
        'from': account.address,
        'gas': 30000000,  # High gas limit for PQ verification
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address)
    })
    
    # Sign and send transaction
    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"📤 Transaction sent: {tx_hash.hex()}")
    
    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    if receipt.status == 1:
        print(f"✅ Registration confirmation successful!")
        print(f"   Gas used: {receipt.gasUsed:,}")
        print(f"   Block: {receipt.blockNumber}")
        return True
    else:
        print(f"❌ Registration confirmation failed!")
        return False

def test_pq_transfer(w3, test_data):
    """Test PQTransferFrom."""
    print("\n🔥 Testing PQTransferFrom")
    print("=" * 50)
    
    # Get first transfer data (Alice transfers to Bob)
    transfer = test_data["pq_transfers"][0]
    
    # Prepare transaction data
    token_id = transfer["token_id"]
    to_address = transfer["to_address"]
    pq_message_bytes = bytes.fromhex(transfer["pq_message"])
    salt_bytes = bytes.fromhex(transfer["pq_signature"]["salt"])
    cs1 = [int(x, 16) for x in transfer["pq_signature"]["cs1"]]
    cs2 = [int(x, 16) for x in transfer["pq_signature"]["cs2"]]
    hint = transfer["pq_signature"]["hint"]
    
    print(f"🎫 Token ID: {token_id}")
    print(f"📨 To Address: {to_address}")
    print(f"📨 PQ Message: {len(pq_message_bytes)} bytes")
    print(f"🖊️  PQ Signature: salt={len(salt_bytes)}B, cs1={len(cs1)} elements, cs2={len(cs2)} elements, hint={hint}")
    
    # Create contract interface
    nft_abi = [{"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"bytes","name":"pqMessage","type":"bytes"},{"internalType":"bytes","name":"salt","type":"bytes"},{"internalType":"uint256[]","name":"cs1","type":"uint256[]"},{"internalType":"uint256[]","name":"cs2","type":"uint256[]"},{"internalType":"uint256","name":"hint","type":"uint256"}],"name":"pqTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"}]
    
    nft = w3.eth.contract(address=to_checksum_address(NFT_CONTRACT_ADDRESS), abi=nft_abi)
    account = Account.from_key(ALICE_PRIVATE_KEY)
    
    # Build transaction with higher gas limit for PQ verification
    tx = nft.functions.pqTransferFrom(
        token_id,
        to_checksum_address(to_address),
        pq_message_bytes,
        salt_bytes,
        cs1,
        cs2,
        hint
    ).build_transaction({
        'from': account.address,
        'gas': 30000000,  # High gas limit for PQ verification
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address)
    })
    
    # Sign and send transaction
    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"📤 Transaction sent: {tx_hash.hex()}")
    
    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    if receipt.status == 1:
        print(f"✅ PQ transfer successful!")
        print(f"   Gas used: {receipt.gasUsed:,}")
        print(f"   Block: {receipt.blockNumber}")
        return True
    else:
        print(f"❌ PQ transfer failed!")
        return False

def main():
    """Run the complete test suite."""
    print("🦅 Testing Complete PQ Registration Flow")
    print("=" * 60)
    
    # Connect to Anvil
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("❌ Failed to connect to Anvil")
        return
    
    print(f"✅ Connected to Anvil (Chain ID: {w3.eth.chain_id})")
    print(f"⚡ Current block: {w3.eth.block_number}")
    
    # Load test vectors
    test_data = load_test_vectors()
    print(f"📋 Loaded test vectors with {len(test_data['registration_intent'])} intents, {len(test_data['registration_confirmation'])} confirmations, {len(test_data['pq_transfers'])} transfers")
    
    # Check Alice's balance
    alice_balance = w3.eth.get_balance(ALICE_ADDRESS)
    print(f"💰 Alice's balance: {w3.from_wei(alice_balance, 'ether')} ETH")
    
    # Test each phase
    results = []
    
    # Test 1: Registration Intent
    results.append(("Registration Intent", test_registration_intent(w3, test_data)))
    
    # Test 2: Registration Confirmation (only if intent succeeded)
    if results[-1][1]:
        results.append(("Registration Confirmation", test_registration_confirmation(w3, test_data)))
    else:
        print("⏭️  Skipping confirmation test due to intent failure")
        results.append(("Registration Confirmation", False))
    
    # Test 3: PQTransferFrom (only if confirmation succeeded)
    if results[-1][1]:
        results.append(("PQTransferFrom", test_pq_transfer(w3, test_data)))
    else:
        print("⏭️  Skipping transfer test due to confirmation failure")
        results.append(("PQTransferFrom", False))
    
    # Summary
    print("\n🎯 Test Results Summary")
    print("=" * 60)
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:25} {status}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    print(f"\n📊 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Full registration flow working!")
    else:
        print("💥 Some tests failed. Check the logs above.")

if __name__ == "__main__":
    main() 