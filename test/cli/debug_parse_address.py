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

    # Test the parseIntentAddress function by calling it directly
    registry_address = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
    
    # Create a simple call to test the parsing
    command = [
        "cast", "call", registry_address,
        "parseIntentAddress(bytes)",
        f"0x{intent_message.hex()}",
        "--rpc-url", "http://localhost:8545"
    ]
    
    print(f"\nTesting parseIntentAddress function:")
    print(" ".join(command))
    
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")

if __name__ == "__main__":
    main() 