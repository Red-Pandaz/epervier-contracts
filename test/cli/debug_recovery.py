import subprocess
from eth_account import Account

def main():
    # Use the default Foundry/Anvil private key
    eth_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    eth_account = Account.from_key(eth_private_key)
    eth_address = eth_account.address

    print(f"Ethereum address: {eth_address}")

    # Create the intent message with correct format: "Register Epervier Key{address}{nonce}"
    nonce = 0
    intent_message = f"Register Epervier Key{eth_address}{nonce}".encode()
    print(f"Intent message: {intent_message}")
    print(f"Intent message hex: {intent_message.hex()}")

    # Test the Epervier recovery using the CLI
    print("\nTesting Epervier signature recovery:")
    
    # First, let's generate a signature using the CLI
    command = [
        "../../ETHFALCON/python-ref/myenv/bin/python",
        "../../ETHFALCON/python-ref/sign_cli.py",
        "sign",
        "--privkey=test_keys/sig_1",
        "--data", intent_message.hex(),
        "--version=epervier"
    ]
    
    print(" ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")

    # Now test the recovery
    if result.returncode == 0:
        # Parse the signature components from the output
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
            print(f"\nExtracted signature components:")
            print(f"Salt: {salt}")
            print(f"Hint: {hint}")
            print(f"cs1 length: {len(cs1)}")
            print(f"cs2 length: {len(cs2)}")
            
            # Test recovery using the CLI
            recovery_command = [
                "../../ETHFALCON/python-ref/myenv/bin/python",
                "../../ETHFALCON/python-ref/sign_cli.py",
                "recover",
                "--pubkey=test_keys/sig_1.pub",
                "--data", intent_message.hex(),
                "--signature", "sig",  # You may need to adjust this to the actual signature file or value
                "--version=epervier"
            ]
            
            print(f"\nTesting recovery:")
            print(" ".join(recovery_command))
            recovery_result = subprocess.run(recovery_command, capture_output=True, text=True)
            print(f"Return code: {recovery_result.returncode}")
            if recovery_result.stdout:
                print(f"STDOUT: {recovery_result.stdout}")
            if recovery_result.stderr:
                print(f"STDERR: {recovery_result.stderr}")

if __name__ == "__main__":
    main() 