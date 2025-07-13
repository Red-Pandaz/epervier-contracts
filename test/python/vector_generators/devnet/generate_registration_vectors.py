#!/usr/bin/env python3
"""
Generate test vectors for registration intent AND confirmation on local Anvil devnet
"""

import json
import sys
import os
import time
from pathlib import Path
from eth_account import Account
from eth_utils import keccak
import subprocess

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.append(str(PROJECT_ROOT / "test/python"))
from eip712_config import DOMAIN_SEPARATOR

# Configuration for local Anvil devnet
DEVNET_CONFIG = {
    "rpc_url": "http://localhost:8545",
    "chain_id": 31337,
    "domain_separator": "0xdc8cb6497956ab682a98a52b5523d0dd4c4be7e17d3b580619ce8de797b2ba3c",
    "contracts": {
        "registry": "0x99bbA657f2BbC93c02D617f8bA121cB8Fc104Acf",
        "nft": "0x67d269191c92Caf3cD7723F116c85e6E9bf55933",
        "epervier_verifier": "0xc6e7DF5E7b4f2A278906862b61205850344D4e7d"
    }
}

# Actor configurations
ALICE_CONFIG = {
    "actor": "alice",
    "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "eth_private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "pq_private_key_file": "private_key_1.pem"
}

BOB_CONFIG = {
    "actor": "bob", 
    "eth_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "eth_private_key": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "pq_private_key_file": "private_key_2.pem"
}

CHARLIE_CONFIG = {
    "actor": "charlie",
    "eth_address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", 
    "eth_private_key": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "pq_private_key_file": "private_key_3.pem"
}

def run_command(command, cwd=None):
    """Run a command and return the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, cwd=cwd)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {command}")
        print(f"Error: {e.stderr}")
        raise

def sign_with_pq_key(message, private_key_file):
    """Sign a message with the PQ private key using the CLI."""
    cwd = PROJECT_ROOT / "ETHFALCON/python-ref"
    
    # Use the virtual environment Python if it exists, otherwise fall back to python3
    venv_python = cwd / "myenv/bin/python3"
    python_cmd = str(venv_python) if venv_python.exists() else "python3"
    
    # Use the CLI to sign the message
    command = f"{python_cmd} sign_cli.py sign --privkey=../../test/test_keys/{private_key_file} --data={message} --version=epervier"
    run_command(command, cwd=cwd)
    
    # Read the signature from the output file
    sig_file = cwd / "sig"
    with open(sig_file, 'r') as f:
        hex_signature = f.read().strip()
    
    # Convert hex string to bytes
    signature_bytes = bytes.fromhex(hex_signature)
    
    # Parse the signature components
    salt = signature_bytes[:40]
    cs1_bytes = signature_bytes[40:40+1024]
    cs2_bytes = signature_bytes[40+1024:40+1024+1024]
    hint_bytes = signature_bytes[40+1024+1024:40+1024+1024+4]
    
    # Convert to arrays
    cs1 = []
    cs2 = []
    for i in range(32):
        cs1_val = int.from_bytes(cs1_bytes[i*32:(i+1)*32], 'big')
        cs2_val = int.from_bytes(cs2_bytes[i*32:(i+1)*32], 'big')
        cs1.append(hex(cs1_val))
        cs2.append(hex(cs2_val))
    
    hint = int.from_bytes(hint_bytes, 'big')
    
    return {
        "salt": salt.hex(),
        "cs1": cs1,
        "cs2": cs2,
        "hint": hint
    }

def generate_pq_signature(message, private_key_file):
    """Generate a PQ signature for the given message."""
    return sign_with_pq_key(message, private_key_file)

def encode_packed(*args):
    """Encode packed data (equivalent to abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
    return result

def get_registration_intent_struct_hash(salt, cs1, cs2, hint, base_pq_message, eth_nonce):
    """Get the struct hash for registration intent EIP-712 signing."""
    # Use the same encodePacked approach as the working test vectors
    type_hash = keccak(text="RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)")
    
    # Convert arrays to uint256[32]
    cs1_array = [int(x, 16) for x in cs1]
    cs2_array = [int(x, 16) for x in cs2]
    
    # Pad arrays to 32 elements
    while len(cs1_array) < 32:
        cs1_array.append(0)
    while len(cs2_array) < 32:
        cs2_array.append(0)
    
    # Use encodePacked approach like the working test vectors
    struct_hash = keccak(encode_packed(
        type_hash,
        keccak(bytes.fromhex(salt)),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1_array])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2_array])),
        hint.to_bytes(32, 'big'),
        keccak(base_pq_message),
        eth_nonce.to_bytes(32, 'big')
    ))
    
    return struct_hash

def get_registration_confirmation_struct_hash(pq_fingerprint, eth_nonce):
    """Get the struct hash for registration confirmation EIP-712 signing."""
    type_hash = keccak(text="RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)")
    
    # Use encodePacked approach like the working test vectors
    struct_hash = keccak(encode_packed(
        type_hash,
        bytes.fromhex(pq_fingerprint[2:]).rjust(32, b'\x00'),  # address pqFingerprint
        eth_nonce.to_bytes(32, 'big')  # uint256 ethNonce
    ))
    
    return struct_hash

def generate_registration_intent_vector(config):
    """Generate registration intent test vector."""
    # Get current nonces (start with 0 for new deployment)
    eth_nonce = 0
    pq_nonce = 0
    
    # Generate salt for PQ signature
    salt = os.urandom(40)
    
    # Create base PQ message for registration intent
    domain_separator = bytes.fromhex(DEVNET_CONFIG["domain_separator"][2:])
    intent_text = "Intent to pair ETH Address "
    eth_address_bytes = bytes.fromhex(config["eth_address"][2:])
    pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')
    
    base_pq_message = domain_separator + intent_text.encode() + eth_address_bytes + pq_nonce_bytes
    
    # Generate PQ signature
    pq_sig = generate_pq_signature(base_pq_message.hex(), config["pq_private_key_file"])
    
    # Create ETH message for registration intent
    eth_message_parts = []
    eth_message_parts.append("Intent to pair Epervier Key".encode())
    eth_message_parts.append(base_pq_message)
    eth_message_parts.append(salt)
    
    # Convert signature components to bytes
    for cs1_hex in pq_sig["cs1"]:
        # cs1_hex is already a hex string like "0x123...", convert to 32-byte big-endian
        cs1_val = int(cs1_hex, 16)
        eth_message_parts.append(cs1_val.to_bytes(32, 'big'))
    for cs2_hex in pq_sig["cs2"]:
        # cs2_hex is already a hex string like "0x123...", convert to 32-byte big-endian
        cs2_val = int(cs2_hex, 16)
        eth_message_parts.append(cs2_val.to_bytes(32, 'big'))
    
    eth_message_parts.append(pq_sig["hint"].to_bytes(32, 'big'))
    eth_message_parts.append(eth_nonce.to_bytes(32, 'big'))
    
    eth_message_bytes = b''.join(eth_message_parts)
    
    # Get struct hash for EIP-712 signing
    struct_hash = get_registration_intent_struct_hash(
        pq_sig["salt"],
        pq_sig["cs1"], 
        pq_sig["cs2"],
        pq_sig["hint"],
        base_pq_message,
        eth_nonce
    )
    
    # Create EIP-712 domain separator
    domain_separator_bytes = bytes.fromhex(DEVNET_CONFIG["domain_separator"][2:])
    
    # Get EIP-712 digest
    eip712_digest = keccak(b'\x19\x01' + domain_separator_bytes + struct_hash)
    
    # Sign with ETH private key using the same method as working vectors
    eth_account = Account.from_key(config["eth_private_key"])
    eth_signature = Account._sign_hash(eip712_digest, private_key=eth_account.key)
    
    return {
        "actor": config["actor"],
        "eth_address": config["eth_address"],
        "eth_private_key": config["eth_private_key"],
        "pq_private_key_file": config["pq_private_key_file"],
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce,
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": pq_sig,
        "eth_message": eth_message_bytes.hex(),
        "eth_signature": {
            "v": eth_signature.v,  # Use v directly like working vectors
            "r": f"0x{eth_signature.r:064x}",
            "s": f"0x{eth_signature.s:064x}"
        },
        "struct_hash": struct_hash.hex(),
        "eip712_digest": eip712_digest.hex()
    }

def generate_registration_confirmation_vector(intent_vector):
    """Generate registration confirmation test vector using the intent vector."""
    # Get nonces (incremented after intent)
    eth_nonce = intent_vector["eth_nonce"] + 1
    pq_nonce = intent_vector["pq_nonce"] + 1
    
    # Compute PQ fingerprint from intent (this would be returned by the verifier)
    # For now, we'll use a deterministic fingerprint based on the PQ key
    base_pq_message_bytes = bytes.fromhex(intent_vector["base_pq_message"])
    pq_fingerprint = "0x" + keccak(base_pq_message_bytes)[:20].hex()
    
    # Create base ETH message for confirmation
    domain_separator = bytes.fromhex(DEVNET_CONFIG["domain_separator"][2:])
    confirmation_text = "Confirm bonding to Epervier Fingerprint "
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
    
    base_eth_message = domain_separator + confirmation_text.encode() + bytes.fromhex(pq_fingerprint[2:]) + eth_nonce_bytes
    
    # Get struct hash for ETH signature
    struct_hash = get_registration_confirmation_struct_hash(pq_fingerprint, eth_nonce)
    
    # Create EIP-712 domain separator
    domain_separator_bytes = bytes.fromhex(DEVNET_CONFIG["domain_separator"][2:])
    
    # Get EIP-712 digest
    eip712_digest = keccak(b'\x19\x01' + domain_separator_bytes + struct_hash)
    
    # Sign with ETH private key using the same method as working vectors
    eth_account = Account.from_key(intent_vector["eth_private_key"])
    eth_signature = Account._sign_hash(eip712_digest, private_key=eth_account.key)
    
    # Create PQ message for confirmation
    pq_message = (
        domain_separator +
        "Confirm bonding to ETH Address ".encode() +
        bytes.fromhex(intent_vector["eth_address"][2:]) +
        base_eth_message +
        bytes([eth_signature.v]) +  # Use v directly like working vectors
        eth_signature.r.to_bytes(32, 'big') +
        eth_signature.s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    
    # Generate PQ signature for confirmation
    pq_sig = generate_pq_signature(pq_message.hex(), intent_vector["pq_private_key_file"])
    
    return {
        "actor": intent_vector["actor"],
        "pq_fingerprint": pq_fingerprint,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce,
        "base_eth_message": base_eth_message.hex(),
        "pq_message": pq_message.hex(),
        "pq_signature": pq_sig,
        "eth_signature": {
            "v": eth_signature.v,  # Use v directly like working vectors
            "r": f"0x{eth_signature.r:064x}",
            "s": f"0x{eth_signature.s:064x}"
        },
        "struct_hash": struct_hash.hex(),
        "eip712_digest": eip712_digest.hex()
    }

def generate_pq_transfer_vectors(alice_intent, bob_intent):
    """Generate PQTransferFrom test vectors."""
    # Compute the PQERC721 domain separator
    # keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), keccak256(bytes("PQERC721")), keccak256(bytes("1")), block.chainid, address(this)))
    
    type_hash = keccak(text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    name_hash = keccak(text="PQERC721")
    version_hash = keccak(text="1")
    chain_id = DEVNET_CONFIG["chain_id"]
    verifying_contract = bytes.fromhex(DEVNET_CONFIG["contracts"]["nft"][2:])
    
    # Encode the domain separator using abi.encode format
    encoded_data = bytearray()
    encoded_data.extend(type_hash)
    encoded_data.extend(name_hash)
    encoded_data.extend(version_hash)
    encoded_data.extend(chain_id.to_bytes(32, 'big'))
    encoded_data.extend(verifying_contract.rjust(32, b'\x00'))
    
    pq_transfer_domain_separator = keccak(encoded_data)
    
    # Generate transfer vectors
    transfers = []
    
    # Transfer 1: Alice transfers her token to Bob
    alice_base_pq_message_bytes = bytes.fromhex(alice_intent["base_pq_message"])
    alice_pq_fingerprint = "0x" + keccak(alice_base_pq_message_bytes)[:20].hex()
    
    # Generate token ID deterministically (same logic as contract)
    alice_token_id = int.from_bytes(keccak(b"PQ_TOKEN" + bytes.fromhex(alice_pq_fingerprint[2:])), 'big')
    
    # Alice transfers to Bob
    alice_pq_nonce = 1  # Incremented after registration confirmation
    timestamp = int(time.time())
    
    # Create PQ transfer message (148 bytes total)
    pq_transfer_message = bytearray()
    pq_transfer_message.extend(pq_transfer_domain_separator)  # 32 bytes
    pq_transfer_message.extend(alice_token_id.to_bytes(32, 'big'))  # 32 bytes
    pq_transfer_message.extend(bytes.fromhex(BOB_CONFIG["eth_address"][2:]).rjust(20, b'\x00'))  # 20 bytes
    pq_transfer_message.extend(alice_pq_nonce.to_bytes(32, 'big'))  # 32 bytes
    pq_transfer_message.extend(timestamp.to_bytes(32, 'big'))  # 32 bytes
    
    # Generate PQ signature for Alice's transfer
    alice_transfer_sig = generate_pq_signature(bytes(pq_transfer_message).hex(), alice_intent["pq_private_key_file"])
    
    transfers.append({
        "description": "Alice transfers her token to Bob",
        "from_actor": "alice",
        "to_actor": "bob",
        "from_address": alice_intent["eth_address"],
        "to_address": BOB_CONFIG["eth_address"],
        "token_id": alice_token_id,
        "pq_fingerprint": alice_pq_fingerprint,
        "pq_nonce": alice_pq_nonce,
        "timestamp": timestamp,
        "pq_transfer_domain_separator": pq_transfer_domain_separator.hex(),
        "pq_message": bytes(pq_transfer_message).hex(),
        "pq_signature": alice_transfer_sig
    })
    
    # Transfer 2: Bob transfers the token back to Alice  
    bob_pq_nonce = 0  # Bob hasn't used any PQ nonces yet
    timestamp2 = timestamp + 60  # 1 minute later
    
    # Create PQ transfer message for Bob transferring back to Alice
    pq_transfer_message2 = bytearray()
    pq_transfer_message2.extend(pq_transfer_domain_separator)  # 32 bytes
    pq_transfer_message2.extend(alice_token_id.to_bytes(32, 'big'))  # 32 bytes (same token)
    pq_transfer_message2.extend(bytes.fromhex(alice_intent["eth_address"][2:]).rjust(20, b'\x00'))  # 20 bytes
    pq_transfer_message2.extend(bob_pq_nonce.to_bytes(32, 'big'))  # 32 bytes
    pq_transfer_message2.extend(timestamp2.to_bytes(32, 'big'))  # 32 bytes
    
    # But wait - Bob can't sign this with his PQ key because the token is tied to Alice's PQ fingerprint
    # Only Alice's PQ key can transfer this token. Let me fix this:
    
    # Actually, looking at the contract, the token can be transferred by:
    # 1. The PQ fingerprint that originally minted it (Alice), OR  
    # 2. The current ETH owner if they're mapped to the original fingerprint
    
    # Since Bob received the token, he's the ETH owner, but he needs to use Alice's PQ key
    # OR Alice needs to transfer it using her PQ key
    
    # Let's create a scenario where Alice (still controlling the PQ key) transfers to Bob again
    alice_pq_nonce2 = alice_pq_nonce + 1  # Alice's nonce incremented again
    
    pq_transfer_message2 = bytearray()
    pq_transfer_message2.extend(pq_transfer_domain_separator)  # 32 bytes
    pq_transfer_message2.extend(alice_token_id.to_bytes(32, 'big'))  # 32 bytes
    pq_transfer_message2.extend(bytes.fromhex(alice_intent["eth_address"][2:]).rjust(20, b'\x00'))  # 20 bytes (back to Alice)
    pq_transfer_message2.extend(alice_pq_nonce2.to_bytes(32, 'big'))  # 32 bytes
    pq_transfer_message2.extend(timestamp2.to_bytes(32, 'big'))  # 32 bytes
    
    # Generate PQ signature for Alice's second transfer (from Bob back to Alice)
    alice_transfer_sig2 = generate_pq_signature(bytes(pq_transfer_message2).hex(), alice_intent["pq_private_key_file"])
    
    transfers.append({
        "description": "Alice transfers token back from Bob to herself (using her PQ key)",
        "from_actor": "alice", 
        "to_actor": "alice",
        "from_address": BOB_CONFIG["eth_address"],  # Current owner is Bob
        "to_address": alice_intent["eth_address"],   # Transferring back to Alice
        "token_id": alice_token_id,
        "pq_fingerprint": alice_pq_fingerprint,
        "pq_nonce": alice_pq_nonce2,
        "timestamp": timestamp2,
        "pq_transfer_domain_separator": pq_transfer_domain_separator.hex(),
        "pq_message": bytes(pq_transfer_message2).hex(),
        "pq_signature": alice_transfer_sig2
    })
    
    return transfers

def main():
    """Generate all test vectors."""
    print("🦅 Generating Devnet Test Vectors")
    print("=" * 50)
    
    # Generate registration intent vectors
    print("📝 Generating registration intent vectors...")
    alice_intent = generate_registration_intent_vector(ALICE_CONFIG)
    bob_intent = generate_registration_intent_vector(BOB_CONFIG)
    charlie_intent = generate_registration_intent_vector(CHARLIE_CONFIG)
    
    print(f"✅ Alice intent: {len(alice_intent['eth_message'])} chars")
    print(f"✅ Bob intent: {len(bob_intent['eth_message'])} chars")
    print(f"✅ Charlie intent: {len(charlie_intent['eth_message'])} chars")
    
    # Generate registration confirmation vectors
    print("📝 Generating registration confirmation vectors...")
    alice_confirmation = generate_registration_confirmation_vector(alice_intent)
    bob_confirmation = generate_registration_confirmation_vector(bob_intent)
    charlie_confirmation = generate_registration_confirmation_vector(charlie_intent)
    
    print(f"✅ Alice confirmation: {len(alice_confirmation['pq_message'])} chars")
    print(f"✅ Bob confirmation: {len(bob_confirmation['pq_message'])} chars")
    print(f"✅ Charlie confirmation: {len(charlie_confirmation['pq_message'])} chars")
    
    # Generate PQTransferFrom vectors
    print("📝 Generating PQTransferFrom vectors...")
    transfer_vectors = generate_pq_transfer_vectors(alice_intent, bob_intent)
    
    print(f"✅ Transfer vectors: {len(transfer_vectors)} transfers")
    for i, transfer in enumerate(transfer_vectors):
        print(f"   {i+1}. {transfer['description']}")
    
    # Create output structure
    output = {
        "devnet_config": DEVNET_CONFIG,
        "registration_intent": {
            "alice": alice_intent,
            "bob": bob_intent,
            "charlie": charlie_intent
        },
        "registration_confirmation": {
            "alice": alice_confirmation,
            "bob": bob_confirmation,
            "charlie": charlie_confirmation
        },
        "pq_transfers": transfer_vectors
    }
    
    # Save to file
    output_file = PROJECT_ROOT / "test/test_vectors/devnet/devnet_registration_vectors.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ Saved complete test vectors to: {output_file}")
    print(f"📊 Total vectors generated: {len(output['registration_intent']) + len(output['registration_confirmation']) + len(output['pq_transfers'])}")

if __name__ == "__main__":
    main() 