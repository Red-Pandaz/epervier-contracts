#!/usr/bin/env python3
"""
Test script for registration confirmation and PQTransferFrom operations
Skips the intent phase (already completed) and focuses on confirmation and transfers
"""

import json
import sys
from web3 import Web3
from eth_account import Account

def load_test_vectors():
    """Load test vectors from the JSON file"""
    with open('../test/test_vectors/devnet/devnet_registration_vectors.json', 'r') as f:
        return json.load(f)

def setup_web3_connection(config):
    """Setup Web3 connection"""
    w3 = Web3(Web3.HTTPProvider(config['rpc_url']))
    if not w3.is_connected():
        raise Exception(f"Failed to connect to {config['rpc_url']}")
    print(f"Connected to chain ID: {w3.eth.chain_id}")
    return w3

def get_contract_abi():
    """Define contract ABIs"""
    return {
        'registrationConfirmation': [
            {
                "inputs": [
                    {"internalType": "address", "name": "pqFingerprint", "type": "address"},
                    {"internalType": "uint256", "name": "ethNonce", "type": "uint256"},
                    {"internalType": "uint8", "name": "v", "type": "uint8"},
                    {"internalType": "bytes32", "name": "r", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "s", "type": "bytes32"},
                    {"internalType": "bytes", "name": "pqSignature", "type": "bytes"}
                ],
                "name": "registrationConfirmation",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ],
        'pqTransferFrom': [
            {
                "inputs": [
                    {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
                    {"internalType": "address", "name": "recipient", "type": "address"},
                    {"internalType": "uint256", "name": "pqNonce", "type": "uint256"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    {"internalType": "bytes", "name": "pqSignature", "type": "bytes"}
                ],
                "name": "pqTransferFrom",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
    }

def encode_pq_signature(pq_sig):
    """Encode PQ signature into bytes format for contract call"""
    # Pack the signature: 40 bytes salt + 32*32 bytes cs1 + 32*32 bytes cs2 + 4 bytes hint
    salt = bytes.fromhex(pq_sig['salt'])
    
    # Convert cs1 and cs2 arrays to bytes, ensuring each element is exactly 32 bytes
    cs1_bytes = b''
    for x in pq_sig['cs1']:
        hex_str = x[2:] if x.startswith('0x') else x  # Remove '0x' prefix if present
        # Pad to 64 characters (32 bytes) if needed
        hex_str = hex_str.zfill(64)
        cs1_bytes += bytes.fromhex(hex_str)
    
    cs2_bytes = b''
    for x in pq_sig['cs2']:
        hex_str = x[2:] if x.startswith('0x') else x  # Remove '0x' prefix if present
        # Pad to 64 characters (32 bytes) if needed
        hex_str = hex_str.zfill(64)
        cs2_bytes += bytes.fromhex(hex_str)
    
    # Pack hint as 4 bytes (big endian)
    hint_bytes = pq_sig['hint'].to_bytes(4, 'big')
    
    return salt + cs1_bytes + cs2_bytes + hint_bytes

def test_registration_confirmation(w3, config, vector, intent_vector):
    """Test registration confirmation"""
    print(f"\n=== Testing Registration Confirmation for {vector['actor']} ===")
    
    # Create contract instance
    contract = w3.eth.contract(
        address=config['contracts']['registry'],
        abi=get_contract_abi()['registrationConfirmation']
    )
    
    # Encode PQ signature
    pq_signature_bytes = encode_pq_signature(vector['pq_signature'])
    
    # Create account for signing (get private key from intent vector)
    account = Account.from_key(intent_vector['eth_private_key'])
    
    print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
    print(f"ETH Nonce: {vector['eth_nonce']}")
    print(f"ETH Signature: v={vector['eth_signature']['v']}, r={vector['eth_signature']['r']}, s={vector['eth_signature']['s']}")
    print(f"PQ Signature Length: {len(pq_signature_bytes)} bytes")
    
    # Build transaction
    tx = contract.functions.registrationConfirmation(
        w3.to_checksum_address(vector['pq_fingerprint']),
        vector['eth_nonce'],
        vector['eth_signature']['v'],
        vector['eth_signature']['r'],
        vector['eth_signature']['s'],
        pq_signature_bytes
    ).build_transaction({
        'from': account.address,
        'gas': 30000000,  # 30M gas for PQ verification
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address)
    })
    
    # Sign and send transaction
    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"Transaction hash: {tx_hash.hex()}")
    
    # Wait for transaction receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction status: {'SUCCESS' if receipt.status == 1 else 'FAILED'}")
    print(f"Gas used: {receipt.gasUsed:,}")
    
    if receipt.status != 1:
        print("Transaction failed!")
        return False
    
    print("Registration confirmation successful!")
    return True

def test_pq_transfer(w3, config, vector):
    """Test PQTransferFrom"""
    print(f"\n=== Testing PQTransferFrom: {vector['description']} ===")
    
    # Create contract instance
    contract = w3.eth.contract(
        address=config['contracts']['nft'],
        abi=get_contract_abi()['pqTransferFrom']
    )
    
    # Encode PQ signature
    pq_signature_bytes = encode_pq_signature(vector['pq_signature'])
    
    # Use Alice's account for all transfers (she owns the PQ key)
    alice_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    account = Account.from_key(alice_key)
    
    print(f"Token ID: {vector['token_id']}")
    print(f"From: {vector['from_address']}")
    print(f"To: {vector['to_address']}")
    print(f"PQ Nonce: {vector['pq_nonce']}")
    print(f"Timestamp: {vector['timestamp']}")
    print(f"PQ Signature Length: {len(pq_signature_bytes)} bytes")
    
    # Build transaction
    tx = contract.functions.pqTransferFrom(
        vector['token_id'],
        w3.to_checksum_address(vector['to_address']),
        vector['pq_nonce'],
        vector['timestamp'],
        pq_signature_bytes
    ).build_transaction({
        'from': account.address,
        'gas': 30000000,  # 30M gas for PQ verification
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address)
    })
    
    # Sign and send transaction
    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"Transaction hash: {tx_hash.hex()}")
    
    # Wait for transaction receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction status: {'SUCCESS' if receipt.status == 1 else 'FAILED'}")
    print(f"Gas used: {receipt.gasUsed:,}")
    
    if receipt.status != 1:
        print("Transaction failed!")
        return False
    
    print("PQTransferFrom successful!")
    return True

def main():
    """Main test function"""
    print("Loading test vectors...")
    vectors = load_test_vectors()
    
    print("Setting up Web3 connection...")
    w3 = setup_web3_connection(vectors['devnet_config'])
    
    # Test registration confirmation for Alice and Bob
    print("\n" + "="*60)
    print("TESTING REGISTRATION CONFIRMATION")
    print("="*60)
    
    alice_confirmation = vectors['registration_confirmation']['alice']
    bob_confirmation = vectors['registration_confirmation']['bob']
    alice_intent = vectors['registration_intent']['alice']
    bob_intent = vectors['registration_intent']['bob']
    
    alice_confirm_success = test_registration_confirmation(w3, vectors['devnet_config'], alice_confirmation, alice_intent)
    bob_confirm_success = test_registration_confirmation(w3, vectors['devnet_config'], bob_confirmation, bob_intent)
    
    # Test PQTransferFrom operations
    print("\n" + "="*60)
    print("TESTING PQ TRANSFERS")
    print("="*60)
    
    transfer_success = []
    for i, transfer_vector in enumerate(vectors['pq_transfers']):
        success = test_pq_transfer(w3, vectors['devnet_config'], transfer_vector)
        transfer_success.append(success)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Alice Registration Confirmation: {'PASS' if alice_confirm_success else 'FAIL'}")
    print(f"Bob Registration Confirmation: {'PASS' if bob_confirm_success else 'FAIL'}")
    
    for i, success in enumerate(transfer_success):
        transfer_desc = vectors['pq_transfers'][i]['description']
        print(f"Transfer {i+1} ({transfer_desc}): {'PASS' if success else 'FAIL'}")
    
    total_tests = 2 + len(transfer_success)
    passed_tests = sum([alice_confirm_success, bob_confirm_success] + transfer_success)
    
    print(f"\nOverall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
