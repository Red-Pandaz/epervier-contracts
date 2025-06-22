import subprocess
import os
import shutil
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct

# Paths
cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref/sign_cli.py'))
python_ref_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref'))
venv_python = os.path.join(python_ref_dir, 'myenv', 'bin', 'python')
key_path = os.path.join(python_ref_dir, 'private_key.pem')
pubkey_path = os.path.join(python_ref_dir, 'public_key.pem')
sig1_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'sig1'))
sig2_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'sig2'))

# Local devnet configuration
rpc_url = "http://localhost:8545"  # Default Anvil RPC
registry_address = None  # Will be set after deployment
epervier_address = None  # Will be set after deployment

# Test messages
msg1 = "Register Epervier Key"
msg2 = "Change Epervier Key"

def run_cli(args):
    original_cwd = os.getcwd()
    os.chdir(python_ref_dir)
    try:
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error:", result.stderr)
            exit(1)
        return result.stdout.strip()
    finally:
        os.chdir(original_cwd)

def run_cli_with_logging(args, description):
    original_cwd = os.getcwd()
    os.chdir(python_ref_dir)
    try:
        print(f"\n--- {description} ---")
        print(f"Command: {' '.join(args)}")
        result = subprocess.run(args, capture_output=True, text=True)
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {repr(result.stdout)}")
        print(f"STDERR: {repr(result.stderr)}")
        if result.returncode != 0:
            print("Error: Command failed with return code", result.returncode)
            print("STDERR:", result.stderr)
            return result.stderr.strip()
        return result.stdout.strip()
    finally:
        os.chdir(original_cwd)

def deploy_contracts():
    """Deploy the Epervier and Registry contracts to local devnet"""
    print("=== Deploying Contracts ===")
    
    # Set a default private key for local testing
    os.environ['PRIVATE_KEY'] = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # Anvil default
    
    # Deploy the contracts
    result = subprocess.run([
        'forge', 'script', 'script/DeployPQRegistry.s.sol:DeployPQRegistry',
        '--rpc-url', rpc_url,
        '--broadcast'
    ], capture_output=True, text=True, cwd='../..')
    
    print("Deploy result:", result.stdout)
    if result.stderr:
        print("Deploy stderr:", result.stderr)
    
    # For now, return placeholder addresses - you'll need to extract from deployment output
    return "0x5FbDB2315678afecb367f032d93F642f64180aa3", "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

def extract_public_key():
    """Extract public key from the generated key file"""
    with open(pubkey_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith('pk = '):
                pk_str = line.split('=')[1].strip()
                # Parse the public key array
                pk_array = eval(pk_str)  # This is safe for our test data
                return [pk_array[0], pk_array[1]]  # Return first two elements as uint256[2]
    return None

def create_registration_message(nonce, public_key, domain_separator, ethereum_address):
    """Create the registration message with domain separator, nonce, public key, and Ethereum address"""
    # Format: DOMAIN_SEPARATOR + "Register Epervier Key" + nonce + publicKey[0] + publicKey[1] + ethereumAddress
    message = domain_separator + f"Register Epervier Key{nonce}{public_key[0]}{public_key[1]}{ethereum_address}"
    return message.encode()

def sign_with_ecdsa(message, private_key):
    """Sign a message with ECDSA"""
    account = Account.from_key(private_key)
    message_hash = encode_defunct(message)
    signed_message = account.sign_message(message_hash)
    return signed_message.signature.hex()

def extract_signature_components(signature_file):
    """Extract signature components from the signature file"""
    with open(signature_file, 'r') as f:
        signature_hex = f.read().strip()
    
    signature_bytes = bytes.fromhex(signature_hex)
    
    # Parse signature components based on Epervier format
    HEAD_LEN = 1
    SALT_LEN = 40
    
    salt = signature_bytes[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = signature_bytes[HEAD_LEN + SALT_LEN:-512*3]  # Remove hint at the end
    
    # For now, return placeholder values - we'd need to implement proper parsing
    # In practice, you'd decompress enc_s to get s1 and s2, then compact them
    return {
        'salt': salt.hex(),
        'cs1': [0] * 32,  # Placeholder - need proper parsing
        'cs2': [0] * 32,  # Placeholder - need proper parsing
        'hint': 0  # Placeholder - need proper parsing
    }

def get_domain_separator(registry_address):
    """Get the domain separator from the registry contract"""
    # For testing, we'll use a placeholder
    # In practice, you'd call the contract to get DOMAIN_SEPARATOR
    return "0x" + "0" * 64  # Placeholder domain separator

def main():
    print("=== PQRegistry Epervier Testing ===")
    
    # 1. Deploy contracts
    global epervier_address, registry_address
    epervier_address, registry_address = deploy_contracts()
    print(f"Epervier deployed at: {epervier_address}")
    print(f"Registry deployed at: {registry_address}")
    
    # 2. Generate keypair
    print("\nGenerating keypair...")
    run_cli([venv_python, "sign_cli.py", "genkeys", "--version", "epervier"])

    # 3. Extract public key
    public_key = extract_public_key()
    if not public_key:
        print("Failed to extract public key")
        return
    print(f"Public key: {public_key}")

    # 4. Create registration message
    nonce = 0  # First registration
    domain_separator = get_domain_separator(registry_address)
    ethereum_address = "0x" + "0" * 40  # Placeholder Ethereum address
    registration_message = create_registration_message(nonce, public_key, domain_separator, ethereum_address)
    print(f"Registration message: {registration_message}")

    # 5. Sign with Epervier
    print("Signing registration message with Epervier...")
    run_cli([venv_python, "sign_cli.py", "sign", "--privkey", key_path, "--data", registration_message.hex()])
    shutil.copy(os.path.join(python_ref_dir, 'sig'), sig1_path)

    # 6. Sign with ECDSA (using the same private key for testing)
    ecdsa_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    ecdsa_signature = sign_with_ecdsa(registration_message, ecdsa_private_key)
    print(f"ECDSA signature: {ecdsa_signature}")

    # 7. Create combined message with ECDSA signature
    combined_message = registration_message + bytes.fromhex(ecdsa_signature[2:])  # Remove 0x prefix
    print(f"Combined message length: {len(combined_message)}")

    # 8. Test recovery on our Epervier contract
    print("\n=== Testing Recovery on Our Contract ===")
    
    recovery_result = run_cli_with_logging([
        venv_python, "sign_cli.py", "recoveronchain", 
        "--signature", sig1_path, 
        "--data", registration_message.hex(), 
        "--pubkey", pubkey_path, 
        "--contractaddress", epervier_address, 
        "--rpc", rpc_url
    ], "Recovery test on our Epervier contract")

    print(f"Recovery result: {recovery_result}")

    # 9. Test registry registration (this would require a more complex setup)
    print("\n=== Registry Registration Test ===")
    print("Note: Full registry testing would require parsing signature components")
    print("and calling the registry contract directly with cast commands")

if __name__ == "__main__":
    main() 