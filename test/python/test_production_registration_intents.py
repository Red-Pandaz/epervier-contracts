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
    """Load production configuration"""
    config_path = "production_config.json"
    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        return None
    
    with open(config_path, 'r') as f:
        return json.load(f)

def load_vectors():
    """Load production registration intent vectors"""
    vectors_path = "../test_vectors/production/register/registration_intent_vectors.json"
    if not os.path.exists(vectors_path):
        print(f"❌ Vectors file not found: {vectors_path}")
        return None
    
    with open(vectors_path, 'r') as f:
        data = json.load(f)
        return data.get('registration_intent', [])

def fund_account(w3, config, from_account, to_address, amount_eth=10):
    """Fund an account with ETH"""
    try:
        # Convert to checksum address
        to_address = Web3.to_checksum_address(to_address)
        from_account = Web3.to_checksum_address(from_account)
        
        # Check current balance
        balance = w3.eth.get_balance(to_address)
        balance_eth = w3.from_wei(balance, 'ether')
        
        if balance_eth >= amount_eth:
            print(f"✅ {to_address} already has sufficient balance: {balance_eth} ETH")
            return True
        
        # Send ETH
        tx = {
            'from': from_account,
            'to': to_address,
            'value': w3.to_wei(amount_eth, 'ether'),
            'gas': 21000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(from_account)
        }
        
        signed_tx = w3.eth.account.sign_transaction(tx, config['deployer_private_key'])
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        
        print(f"✅ Funded {to_address} with {amount_eth} ETH")
        return True
        
    except Exception as e:
        print(f"❌ Failed to fund {to_address}: {e}")
        return False

def test_registration_intent(w3, config, vector):
    """Test a single registration intent vector"""
    try:
        actor_name = vector.get('actor', 'unknown')
        eth_address = vector.get('eth_address', '')
        
        print(f"\n🔍 Testing {actor_name} ({eth_address})")
        
        # Extract the ETH message and signature components from the vector
        eth_message = bytes.fromhex(vector['eth_message'])
        eth_signature = vector['eth_signature']
        v = eth_signature['v']
        r = bytes.fromhex(eth_signature['r'][2:])  # Convert hex string to bytes32
        s = bytes.fromhex(eth_signature['s'][2:])  # Convert hex string to bytes32
        
        print(f"✅ Extracted ETH message: {len(eth_message)} bytes")
        print(f"✅ Extracted signature: v={v}, r={eth_signature['r']}, s={eth_signature['s']}")
        
        # Prepare transaction (always from deployer)
        deployer_address = Web3.to_checksum_address(config['deployer_address'])
        # Contract address from devnet deployment
        registry_address = Web3.to_checksum_address(config['pq_registry_address'])
        
        # Create contract instance with ABI
        # PQRegistry ABI for submitRegistrationIntent function
        abi = [
            {
                "inputs": [
                    {"internalType": "bytes", "name": "ethMessage", "type": "bytes"},
                    {"internalType": "uint8", "name": "v", "type": "uint8"},
                    {"internalType": "bytes32", "name": "r", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "s", "type": "bytes32"}
                ],
                "name": "submitRegistrationIntent",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
        
        contract = w3.eth.contract(address=registry_address, abi=abi)
        
        # Call the function directly like the Solidity script does
        print(f"✅ Calling submitRegistrationIntent directly...")
        
        # Prepare transaction
        tx = contract.functions.submitRegistrationIntent(
            eth_message, v, r, s
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
            print(f"✅ Registration intent successful for {actor_name}")
            print(f"   Gas used: {receipt['gasUsed']:,}")
            return True
        else:
            print(f"❌ Registration intent failed for {actor_name}")
            return False
            
    except Exception as e:
        print(f"❌ Registration intent failed for {actor_name}: {e}")
        return False

def main():
    print("🚀 Testing Production Registration Intent Vectors")
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
    
    print(f"📋 Loaded {len(vectors)} registration intent vectors")
    
    # Fund production accounts
    print("💰 Funding production accounts...")
    for vector in vectors:
        eth_address = vector.get('eth_address', '')
        if eth_address:
            fund_account(w3, config, config['deployer_address'], eth_address)
    
    # Test each vector
    print(f"\n📊 Progress: 0/{len(vectors)}")
    success_count = 0
    
    for i, vector in enumerate(vectors, 1):
        print(f"\n📊 Progress: {i}/{len(vectors)}")
        if test_registration_intent(w3, config, vector):
            success_count += 1
    
    print(f"\n🎯 Results: {success_count}/{len(vectors)} successful")
    print(f"📈 Success Rate: {success_count/len(vectors)*100:.1f}%")

if __name__ == "__main__":
    main() 