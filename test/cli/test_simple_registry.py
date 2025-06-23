#!/usr/bin/env python3
import subprocess
import os
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct

# Paths
python_ref_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref'))
venv_python = os.path.join(python_ref_dir, 'myenv', 'bin', 'python')
key_path = os.path.join(python_ref_dir, 'private_key.pem')
pubkey_path = os.path.join(python_ref_dir, 'public_key.pem')

# Contract addresses (from your deployment)
EPERVIER_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
REGISTRY_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
RPC_URL = "http://localhost:8545"

def run_cli(args, description=""):
    """Run CLI command and return output"""
    original_cwd = os.getcwd()
    os.chdir(python_ref_dir)
    try:
        print(f"\n--- {description} ---")
        print(f"Command: {' '.join(args)}")
        result = subprocess.run(args, capture_output=True, text=True)
        print(f"Return code: {result.returncode}")
        if result.returncode != 0:
            print(f"STDERR: {result.stderr}")
            return None
        return result.stdout.strip()
    finally:
        os.chdir(original_cwd)

def generate_keypair():
    """Generate Epervier keypair"""
    print("Generating Epervier keypair...")
    result = run_cli([venv_python, "sign_cli.py", "genkeys", "--version", "epervier"], "Generate keypair")
    return result is not None

def get_public_key():
    """Extract public key from generated file"""
    try:
        with open(pubkey_path, 'r') as f:
            content = f.read()
            # Look for the public key in the format: pk = <number>
            import re
            match = re.search(r'pk\s*=\s*(\d+)', content)
            if match:
                pk_value = int(match.group(1))
                # For Epervier, we need to split this into two uint256 values
                # This is a simplified approach - in practice you'd need proper parsing
                pk_high = pk_value >> 128
                pk_low = pk_value & ((1 << 128) - 1)
                return [pk_low, pk_high]
    except Exception as e:
        print(f"Error reading public key: {e}")
    return None

def create_intent_message(ethereum_address, nonce):
    """Create intent message for registration"""
    # Format: "Register Epervier Key" + ethereum_address + nonce
    message = f"Register Epervier Key{ethereum_address}{nonce}"
    return message.encode()

def sign_message(message):
    """Sign message with Epervier key"""
    print(f"Signing message: {message.hex()}")
    result = run_cli([
        venv_python, "sign_cli.py", "sign", 
        "--privkey", key_path, 
        "--data", message.hex()
    ], "Sign message")
    return result is not None

def test_recovery():
    """Test signature recovery on the deployed contract"""
    # Create a test message
    test_message = b"Test message for recovery"
    
    # Sign it
    if not sign_message(test_message):
        print("Failed to sign message")
        return False
    
    # Test recovery
    result = run_cli([
        venv_python, "sign_cli.py", "recoveronchain",
        "--signature", os.path.join(python_ref_dir, 'sig'),
        "--data", test_message.hex(),
        "--pubkey", pubkey_path,
        "--contractaddress", EPERVIER_ADDRESS,
        "--rpc", RPC_URL
    ], "Test recovery on deployed contract")
    
    return result is not None

def test_registry_intent():
    """Test submitting registration intent to the registry"""
    # Get public key
    public_key = get_public_key()
    if not public_key:
        print("Failed to get public key")
        return False
    
    print(f"Public key: {public_key}")
    
    # Create intent message
    ethereum_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Anvil account 1
    nonce = 0
    intent_message = create_intent_message(ethereum_address, nonce)
    
    print(f"Intent message: {intent_message}")
    
    # Sign intent message
    if not sign_message(intent_message):
        print("Failed to sign intent message")
        return False
    
    # For now, just test that we can sign and recover
    # In a full test, we'd parse the signature and call the registry contract
    print("Successfully signed intent message")
    return True

def main():
    print("=== Simple Registry Test ===")
    
    # 1. Generate keypair
    if not generate_keypair():
        print("Failed to generate keypair")
        return
    
    # 2. Test recovery on deployed contract
    if not test_recovery():
        print("Recovery test failed")
        return
    
    # 3. Test registry intent creation
    if not test_registry_intent():
        print("Registry intent test failed")
        return
    
    print("\n=== All tests passed! ===")
    print("Next steps:")
    print("1. Parse signature components (salt, cs1, cs2, hint)")
    print("2. Call registry.submitRegistrationIntent() with cast")
    print("3. Test the full two-step registration process")

if __name__ == "__main__":
    main() 