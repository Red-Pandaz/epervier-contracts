import subprocess
import os
import shutil
import json
import time

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
contract_address = None  # Will be set after deployment

msg1 = "first message"
msg2 = "second message"
msg3 = "third message"
msg4 = "fourth message"

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

def deploy_contract():
    """Deploy the Epervier contract to local devnet"""
    print("=== Deploying Epervier Contract ===")
    
    # Set a default private key for local testing
    os.environ['PRIVATE_KEY'] = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # Anvil default
    
    # Deploy the contract
    result = subprocess.run([
        'forge', 'script', 'script/DeployLocalEpervier.s.sol:DeployLocalEpervier',
        '--rpc-url', rpc_url,
        '--broadcast'
    ], capture_output=True, text=True, cwd='../..')
    
    print("Deploy result:", result.stdout)
    if result.stderr:
        print("Deploy stderr:", result.stderr)
    
    # Extract contract address from deployment
    # This is a simple approach - in practice you'd parse the deployment output
    # For now, we'll use a placeholder and you can set it manually
    return "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Default Anvil first contract

def main():
    print("=== Local Epervier Testing ===")
    
    # 1. Deploy contract
    global contract_address
    contract_address = deploy_contract()
    print(f"Contract deployed at: {contract_address}")
    
    # 2. Generate keypair
    print("\nGenerating keypair...")
    run_cli([venv_python, "sign_cli.py", "genkeys", "--version", "epervier"])

    # 3. Sign messages
    print("Signing first message...")
    run_cli([venv_python, "sign_cli.py", "sign", "--privkey", key_path, "--data", msg1.encode().hex()])
    shutil.copy(os.path.join(python_ref_dir, 'sig'), sig1_path)

    print("Signing second message...")
    run_cli([venv_python, "sign_cli.py", "sign", "--privkey", key_path, "--data", msg2.encode().hex()])
    shutil.copy(os.path.join(python_ref_dir, 'sig'), sig2_path)

    # 4. Test recoveries
    print("\n=== Testing Local Contract Recoveries ===")
    
    print1 = run_cli_with_logging([
        venv_python, "sign_cli.py", "recoveronchain", 
        "--signature", sig1_path, 
        "--data", msg1.encode().hex(), 
        "--pubkey", pubkey_path, 
        "--contractaddress", contract_address, 
        "--rpc", rpc_url
    ], "Recovery 1: sig1 + msg1 (correct match)")

    print2 = run_cli_with_logging([
        venv_python, "sign_cli.py", "recoveronchain", 
        "--signature", sig2_path, 
        "--data", msg2.encode().hex(), 
        "--pubkey", pubkey_path, 
        "--contractaddress", contract_address, 
        "--rpc", rpc_url
    ], "Recovery 2: sig2 + msg2 (correct match)")

    print("\n=== Results ===")
    print("Recovered print 1:", print1)
    print("Recovered print 2:", print2)
    
    if print1 == print2:
        print("✅ PASS: Same key, different messages, same recovery")
    else:
        print("❌ FAIL: Different recoveries")

if __name__ == "__main__":
    main() 