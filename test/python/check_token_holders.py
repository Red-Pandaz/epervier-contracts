#!/usr/bin/env python3

import os
import sys
from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to OP Sepolia
w3 = Web3(Web3.HTTPProvider('https://sepolia.optimism.io'))

# PQERC721 contract address
contract_address = '0x9f6A2b8560FceF521ACe81c651CFd8A07381B950'

# Basic ERC721 ABI for checking holders
abi = [
    {
        "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
        "name": "ownerOf",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def main():
    print("🔍 Checking PQERC721 Token Holders")
    print("=" * 50)
    
    try:
        # Create contract instance
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Check total supply
        try:
            total_supply = contract.functions.totalSupply().call()
            print(f"📊 Total Supply: {total_supply}")
        except Exception as e:
            print(f"⚠️  Could not get total supply: {e}")
            total_supply = 5  # Assume 5 tokens based on our test
        
        print(f"\n🔍 Checking token holders for {total_supply} tokens:")
        print("-" * 50)
        
        # Check each token
        for i in range(total_supply):
            try:
                owner = contract.functions.ownerOf(i).call()
                balance = contract.functions.balanceOf(owner).call()
                print(f"Token {i}: Owner {owner} (Balance: {balance})")
            except Exception as e:
                print(f"Token {i}: Error - {e}")
        
        print("\n✅ Token holder check complete!")
        
    except Exception as e:
        print(f"❌ Error connecting to contract: {e}")

if __name__ == "__main__":
    main() 