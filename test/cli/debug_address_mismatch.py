import subprocess
from eth_account import Account
import os
import sys

# Add the python-ref directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref')))
from falcon_epervier import HEAD_LEN, SALT_LEN, decompress
from common import falcon_compact, q
from polyntt.poly import Poly

def parse_signature_like_cli(sig_path):
    with open(sig_path, 'r') as f:
        sig_hex = f.read().strip()
    sig = bytes.fromhex(sig_hex)
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:-512*3]
    s = decompress(enc_s, 666*2 - HEAD_LEN - SALT_LEN, 512*2)
    mid = len(s) // 2
    s = [elt % q for elt in s]
    s1, s2 = s[:mid], s[mid:]
    s1_compact = falcon_compact(s1)
    s2_compact = falcon_compact(s2)
    s2_inv_ntt = Poly(s2, q).inverse().ntt()
    hint = 1
    for elt in s2_inv_ntt:
        hint = (hint * elt) % q
    return {
        'salt': salt.hex(),
        'cs1': s1_compact,
        'cs2': s2_compact,
        'hint': hint
    }

def main():
    # 1. Use the default Foundry/Anvil private key
    eth_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    eth_account = Account.from_key(eth_private_key)
    eth_address = eth_account.address

    print(f"Ethereum address from private key: {eth_address}")

    # 2. Generate the intent message
    nonce = 0
    intent_message = f"Register Epervier Key{eth_address}{nonce}".encode()
    print(f"Intent message: {intent_message}")
    print(f"Intent message hex: {intent_message.hex()}")

    # 3. Sign the message using your CLI
    print("\nSigning message...")
    subprocess.run([
        "python", "../../ETHFALCON/python-ref/sign_cli.py", "sign",
        "--privkey", "../../ETHFALCON/python-ref/private_key.pem",
        "--data", intent_message.hex()
    ], check=True)

    # 4. Test recovery on the Epervier contract
    print("\nTesting recovery on Epervier contract...")
    result = subprocess.run([
        "python", "../../ETHFALCON/python-ref/sign_cli.py", "recoveronchain",
        "--signature", "../../ETHFALCON/python-ref/sig",
        "--data", intent_message.hex(),
        "--pubkey", "../../ETHFALCON/python-ref/public_key.pem",
        "--contractaddress", "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "--rpc", "http://localhost:8545"
    ], capture_output=True, text=True)
    
    print(f"Recovery result: {result.stdout.strip()}")
    
    # 5. Parse the signature to see the components
    sig_components = parse_signature_like_cli('../../ETHFALCON/python-ref/sig')
    print(f"\nSignature components:")
    print(f"Salt: {sig_components['salt']}")
    print(f"Hint: {sig_components['hint']}")

if __name__ == "__main__":
    main() 