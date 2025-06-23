import subprocess
import json
from eth_account import Account
from eth_account.messages import encode_defunct

def main():
    # Use the default Foundry/Anvil private key
    eth_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    eth_account = Account.from_key(eth_private_key)
    eth_address = eth_account.address

    print(f"Ethereum address: {eth_address}")

    # Create the confirmation message
    # Format should match what the contract expects
    nonce = 0  # Should match the nonce from intent
    confirmation_message = f"Confirm Epervier Registration{eth_address}{nonce}".encode()
    print(f"Confirmation message: {confirmation_message}")
    print(f"Confirmation message hex: {confirmation_message.hex()}")

    # Step 1: Sign with ECDSA (ETH private key)
    print("\nStep 1: Signing with ECDSA...")
    message_hash = encode_defunct(confirmation_message)
    ecdsa_signed_message = eth_account.sign_message(message_hash)
    ecdsa_signature = ecdsa_signed_message.signature.hex()
    print(f"ECDSA signature: {ecdsa_signature}")

    # Step 2: Sign with Epervier key
    print("\nStep 2: Signing with Epervier key...")
    command = [
        "../../ETHFALCON/python-ref/myenv/bin/python", 
        "../../ETHFALCON/python-ref/sign_cli.py",
        "sign",
        "--privkey=test_keys/sig_1",
        "--data", confirmation_message.hex(),
        "--version=epervier"
    ]
    
    print(" ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")

    # Parse the Epervier signature components
    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        salt = None
        cs1 = []
        cs2 = []
        hint = None
        
        for line in lines:
            if line.startswith("Salt:"):
                salt = line.split(": ")[1]
            elif line.startswith("Hint:"):
                hint = line.split(": ")[1]
            elif line.startswith("cs1:"):
                cs1_str = line.split(": ")[1]
                cs1 = [int(x.strip()) for x in cs1_str.strip('[]').split(',')]
            elif line.startswith("cs2:"):
                cs2_str = line.split(": ")[1]
                cs2 = [int(x.strip()) for x in cs2_str.strip('[]').split(',')]
        
        if salt and cs1 and cs2 and hint is not None:
            print(f"\nExtracted Epervier signature components:")
            print(f"Salt: {salt}")
            print(f"Hint: {hint}")
            print(f"cs1 length: {len(cs1)}")
            print(f"cs2 length: {len(cs2)}")
            
            # Step 3: Submit confirmation to contract
            print("\nStep 3: Submitting confirmation to contract...")
            registry_address = "0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1"
            rpc_url = "http://localhost:8545"
            
            command = [
                "cast", "send", registry_address,
                "confirmRegistration(bytes,bytes,bytes,uint256[],uint256[],uint256,uint256)",
                f"0x{confirmation_message.hex()}",
                ecdsa_signature,
                f"0x{salt}",
                "[" + ",".join(map(str, cs1)) + "]",
                "[" + ",".join(map(str, cs2)) + "]",
                str(hint),
                str(nonce),
                "--rpc-url", rpc_url,
                "--private-key", eth_private_key,
                "--gas-limit", "5000000"
            ]
            
            print(" ".join(command))
            result = subprocess.run(command, capture_output=True, text=True)
            print(f"Return code: {result.returncode}")
            if result.stdout:
                print(f"STDOUT: {result.stdout}")
            if result.stderr:
                print(f"STDERR: {result.stderr}")

if __name__ == "__main__":
    main() 