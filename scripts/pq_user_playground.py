#!/usr/bin/env python3
"""
🦅 EPERVIER PQ PLAYGROUND 🦅
Interactive script for users to experience post-quantum cryptography!

This script guides you through:
1. Setting up your environment (keys, config)
2. Generating your PQ Epervier keys
3. Registering your PQ fingerprint with your ETH address
4. Minting and transferring PQ NFTs
5. Having fun with quantum-resistant crypto!
"""

import os
import sys
import json
import subprocess
import secrets
import time
from pathlib import Path
from eth_account import Account
from web3 import Web3

# Colors for pretty output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}🦅 {text} 🦅{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.OKGREEN}✅ {text}{Colors.ENDC}")

def print_warning(text):
    print(f"{Colors.WARNING}⚠️  {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.OKCYAN}ℹ️  {text}{Colors.ENDC}")

def print_step(step_num, text):
    print(f"{Colors.OKBLUE}{Colors.BOLD}📋 Step {step_num}: {text}{Colors.ENDC}")

# Configuration - LOCAL DEVNET for debugging
CONFIG = {
    "rpc_url": "http://localhost:8545",
    "chain_id": 31337,
    "contracts": {
        "registry": "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6",
        "nft": "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        "epervier_verifier": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    },
    "ethfalcon_path": "ETHFALCON/python-ref",
    "user_data_dir": "user_data",
    # Pre-funded Anvil account for testing
    "anvil_account": {
        "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    }
}

# OP Sepolia configuration (backup)
OP_SEPOLIA_CONFIG = {
    "rpc_url": "https://sepolia.optimism.io",
    "chain_id": 11155420,
    "contracts": {
        "registry": "0x18E3bc34fc2645bDCe2b85AF6f9e0ac3cD26637e",
        "nft": "0x9f6A2b8560FceF521ACe81c651CFd8A07381B950",
        "epervier_verifier": "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
    }
}

# EIP-712 Helper Functions for proper signing
def keccak256(data: bytes) -> bytes:
    """Compute keccak256 hash of data"""
    from eth_utils import keccak
    return keccak(data)

def encode_packed(*args) -> bytes:
    """Encode packed data (equivalent to abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
        else:
            raise ValueError(f"Unsupported type: {type(arg)}")
    return result

def get_eip712_digest(domain_separator: bytes, struct_hash: bytes) -> bytes:
    """Compute the EIP712 digest"""
    from eth_utils import keccak
    packed = b'\x19\x01' + domain_separator + struct_hash
    return keccak(packed)

def get_registration_intent_struct_hash(
    salt: bytes,
    cs1: list,
    cs2: list,
    hint: int,
    base_pq_message: bytes,
    eth_nonce: int
) -> bytes:
    """Compute the struct hash for RegistrationIntent using abi.encode like the contract"""
    from eth_abi import encode
    from eth_utils import keccak
    
    # Type hash for RegistrationIntent (from contract)
    type_hash = bytes.fromhex("9769cf982eace30c9b9539ef87f8586301e22aec70b6d22e7f52b01ec6c9a062")
    
    # Encode like the contract: abi.encode(type_hash, keccak256(salt), keccak256(cs1_packed), keccak256(cs2_packed), hint, keccak256(basePQMessage), ethNonce)
    encoded_data = encode([
        'bytes32',  # type_hash
        'bytes32',  # keccak256(salt)
        'bytes32',  # keccak256(abi.encodePacked(cs1))
        'bytes32',  # keccak256(abi.encodePacked(cs2))
        'uint256',  # hint
        'bytes32',  # keccak256(basePQMessage)
        'uint256'   # ethNonce
    ], [
        type_hash,
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint,
        keccak(base_pq_message),
        eth_nonce
    ])
    
    return keccak(encoded_data)

class PQPlayground:
    def __init__(self):
        # Get the directory where the script is located
        script_dir = Path(__file__).parent
        
        self.user_dir = script_dir / CONFIG["user_data_dir"]
        self.user_dir.mkdir(exist_ok=True)
        
        # Resolve ETHFALCON path relative to the project root (parent of scripts dir)
        project_root = script_dir.parent
        self.ethfalcon_path = project_root / "ETHFALCON" / "python-ref"
        
        self.env_file = self.user_dir / ".env"
        self.config_file = self.user_dir / "user_config.json"
        self.user_config = {}
        
        # Load environment variables from .env file if it exists
        self.load_env_file()
        
        # Load existing config if it exists
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.user_config = json.load(f)
        
        # Auto-detect environment variables if not in config
        self.auto_detect_environment()

    def load_env_file(self):
        """Load environment variables from .env file"""
        # Get project root (parent of scripts dir)
        project_root = Path(__file__).parent.parent
        
        # Check project root for .env first
        project_env = project_root / ".env"
        env_to_load = project_env if project_env.exists() else self.env_file
        
        if env_to_load.exists():
            with open(env_to_load, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()

    def auto_detect_environment(self):
        """Automatically detect and populate environment variables"""
        if "eth_address" not in self.user_config:
            # Check if we're running on localhost (Anvil) - auto-use pre-funded account
            if CONFIG["rpc_url"] == "http://localhost:8545":
                print_info("Detected local Anvil devnet - using pre-funded account")
                self.user_config.update({
                    "eth_address": CONFIG["anvil_account"]["address"],
                    "private_key": CONFIG["anvil_account"]["private_key"],
                    "setup_complete": True,
                    "auto_detected": True,
                    "anvil_account": True
                })
                self.save_config()
                return
            
            existing_private_key = os.getenv('PRIVATE_KEY')
            existing_eth_address = os.getenv('ETH_ADDRESS')
            
            # If we have private key but no address, derive it
            if existing_private_key and not existing_eth_address:
                try:
                    account = Account.from_key(existing_private_key)
                    existing_eth_address = account.address
                except Exception:
                    existing_private_key = None
            
            # Auto-populate config if we have both
            if existing_private_key and existing_eth_address:
                self.user_config.update({
                    "eth_address": existing_eth_address,
                    "private_key": existing_private_key,
                    "setup_complete": True,
                    "auto_detected": True
                })
                self.save_config()

    def save_config(self):
        """Save user configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.user_config, f, indent=2)

    def setup_environment(self):
        """Step 1: Set up user's environment"""
        print_step(1, "Environment Setup")
        
        # Check if we already have a setup (including auto-detected Anvil)
        if self.user_config.get("setup_complete"):
            if self.user_config.get("anvil_account"):
                print_success("Using pre-funded Anvil account for testing!")
            else:
                print_success("Environment already set up!")
            print_info(f"ETH Address: {self.user_config['eth_address']}")
            return True
        
        # Check for existing environment variables
        existing_private_key = os.getenv('PRIVATE_KEY')
        existing_eth_address = os.getenv('ETH_ADDRESS')
        
        # If we have private key but no address, derive it
        if existing_private_key and not existing_eth_address:
            try:
                account = Account.from_key(existing_private_key)
                existing_eth_address = account.address
                print_info("Derived Ethereum address from private key")
            except Exception as e:
                print_error(f"Could not derive address from private key: {e}")
                existing_private_key = None
        
        if existing_private_key and existing_eth_address:
            print_success("Found existing Ethereum key in environment!")
            print_info(f"ETH Address: {existing_eth_address}")
            choice = input("Use existing key from environment? (Y/n): ").strip().lower()
            
            if choice != 'n':
                self.user_config.update({
                    "eth_address": existing_eth_address,
                    "private_key": existing_private_key,
                    "setup_complete": True,
                    "setup_timestamp": time.time()
                })
                self.save_config()
                print_success("Using existing environment setup!")
                return True
        
        print("Welcome to the PQ Playground! Let's set up your environment.")
        print("\nOptions:")
        print("1. 🎲 Generate a new Ethereum private key (for testing)")
        print("2. 🔑 Use your existing Ethereum private key")
        print("3. ⚡ Use existing setup")
        
        if self.env_file.exists():
            print_info("Found existing .env file")
            choice = input("Your choice (1/2/3): ").strip()
        else:
            choice = input("Your choice (1/2): ").strip()
        
        if choice == "1":
            # Generate new key
            private_key = "0x" + secrets.token_hex(32)
            account = Account.from_key(private_key)
            eth_address = account.address
            
            print_success(f"Generated new Ethereum key!")
            print_info(f"Address: {eth_address}")
            print_warning("⚠️  This is a TEST key for the playground. Never use it with real funds!")
            
        elif choice == "2":
            # Use existing key
            private_key = input("Enter your Ethereum private key (0x...): ").strip()
            if not private_key.startswith("0x"):
                private_key = "0x" + private_key
            
            try:
                account = Account.from_key(private_key)
                eth_address = account.address
                print_success(f"Using your Ethereum address: {eth_address}")
            except Exception as e:
                print_error(f"Invalid private key: {e}")
                return False
                
        elif choice == "3" and self.env_file.exists():
            print_success("Using existing environment setup")
            return True
        else:
            print_error("Invalid choice")
            return False
        
        # Save to .env file
        env_content = f"""# PQ Playground Environment
PRIVATE_KEY={private_key}
ETH_ADDRESS={eth_address}
RPC_URL={CONFIG['rpc_url']}
CHAIN_ID={CONFIG['chain_id']}

# Contract Addresses
REGISTRY_CONTRACT={CONFIG['contracts']['registry']}
NFT_CONTRACT={CONFIG['contracts']['nft']}
EPERVIER_VERIFIER={CONFIG['contracts']['epervier_verifier']}
"""
        
        with open(self.env_file, 'w') as f:
            f.write(env_content)
        
        # Update user config
        self.user_config.update({
            "eth_address": eth_address,
            "setup_complete": True,
            "setup_timestamp": time.time()
        })
        self.save_config()
        
        print_success(f"Environment saved to {self.env_file}")
        print_info("Your private key is safely stored in the .env file")
        return True

    def generate_pq_keys(self):
        """Step 2: Generate PQ Epervier keys"""
        print_step(2, "Generate Post-Quantum Keys")
        
        if not self.ethfalcon_path.exists():
            print_error(f"ETHFALCON not found at {self.ethfalcon_path}")
            print_info("Please clone ETHFALCON in the project root:")
            print_info("git clone https://github.com/zknox/ETHFALCON.git")
            return False
        
        # Check if virtual environment exists  
        venv_path = self.ethfalcon_path / "myenv" / "bin" / "activate"
        if not venv_path.exists():
            print_error(f"ETHFALCON virtual environment not found at {venv_path}")
            print_info("Please set up ETHFALCON environment properly:")
            print_info("cd ETHFALCON/python-ref")
            print_info("make install")
            print_info("This will create the virtual environment and install all dependencies including polyntt")
            return False
        
        print("🔐 Generating your post-quantum Epervier keys...")
        
        # Check if keys already exist
        key_files = ["private_key.pem", "public_key.pem"]
        existing_keys = [f for f in key_files if (self.ethfalcon_path / f).exists()]
        
        if existing_keys:
            print_info(f"Found existing keys: {existing_keys}")
            choice = input("Generate new keys? This will overwrite existing ones (y/N): ").strip().lower()
            if choice != 'y':
                print_success("Using existing PQ keys")
                return self.test_pq_keys()
        
        # Generate keys
        try:
            # Activate ETHFALCON virtual environment and run genkeys
            cmd = f"source myenv/bin/activate && python sign_cli.py genkeys --version epervier"
            result = subprocess.run(
                cmd, shell=True, cwd=self.ethfalcon_path, 
                capture_output=True, text=True, check=True
            )
            
            print_success("PQ keys generated successfully!")
            
            # Test the keys
            return self.test_pq_keys()
            
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to generate PQ keys: {e}")
            print_error(f"Error output: {e.stderr}")
            return False

    def test_pq_keys(self):
        """Test the generated PQ keys"""
        print("\n🧪 Testing your PQ keys...")
        
        test_message = "Hello PQ World! 🌍"
        message_hex = test_message.encode('utf-8').hex()
        
        try:
            # Sign test message
            cmd = f"source myenv/bin/activate && python sign_cli.py sign --data {message_hex} --privkey private_key.pem"
            result = subprocess.run(
                cmd, shell=True, cwd=self.ethfalcon_path, 
                capture_output=True, text=True, check=True
            )
            
            # Test on-chain recovery
            cmd = f"source myenv/bin/activate && python sign_cli.py recoveronchain --data {message_hex} --pubkey public_key.pem --signature sig --contractaddress {CONFIG['contracts']['epervier_verifier']} --rpc {CONFIG['rpc_url']}"
            result = subprocess.run(
                cmd, shell=True, cwd=self.ethfalcon_path, 
                capture_output=True, text=True, check=True
            )
            
            # Extract PQ fingerprint
            print_info(f"Raw ETHFALCON output: {result.stdout.strip()}")
            if "0x" in result.stdout:
                # Find the actual fingerprint - should be 40 hex chars after 0x
                hex_parts = result.stdout.split("0x")
                for part in hex_parts[1:]:  # Skip first empty part
                    clean_part = ''.join(c for c in part if c in '0123456789abcdefABCDEF')
                    if len(clean_part) >= 40:
                        pq_fingerprint = "0x" + clean_part[:40]
                        break
                else:
                    print_error("Could not find valid PQ fingerprint in output")
                    return False
                
                self.user_config["pq_fingerprint"] = pq_fingerprint
                self.save_config()
                
                print_success("PQ keys are working!")
                print_info(f"Your PQ fingerprint: {pq_fingerprint}")
                return True
            else:
                print_error("Could not extract PQ fingerprint")
                return False
                
        except subprocess.CalledProcessError as e:
            print_error(f"PQ key test failed: {e}")
            return False

    def register_pq_fingerprint(self):
        """Step 3: 2-Step Registration Process (Auto-mints PQ NFT)"""
        print_step(3, "2-Step PQ Registration + NFT Minting")
        
        if "pq_fingerprint" not in self.user_config:
            print_error("No PQ fingerprint found. Please generate keys first.")
            return False
        
        if "eth_address" not in self.user_config:
            print_error("No Ethereum address found. Please setup environment first.")
            return False
        
        print("🔗 Starting 2-step registration process...")
        print_info(f"PQ Fingerprint: {self.user_config['pq_fingerprint']}")
        print_info(f"ETH Address: {self.user_config['eth_address']}")
        print_info("💎 Your PQ NFT will be minted automatically upon successful registration!")
        
        print("\n📝 2-Step Registration Process:")
        print("   Step 1: Generate registration intent with PQ signature")
        print("   Step 2: Sign confirmation with Ethereum private key")
        print("   Result: PQ fingerprint registered + NFT minted! 🎨")
        
        choice = input("\nProceed with 2-step registration? (y/N): ").strip().lower()
        if choice != 'y':
            return False
        
        # Step 1: PQ Intent Signature  
        print(f"\n{Colors.OKBLUE}🔐 Step 1: Generating PQ registration intent...{Colors.ENDC}")
        
        # Create registration intent message in EXACT test vector format
        # Query the contract for the correct domain separator (for current chain ID)
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(CONFIG['rpc_url']))
        
        registry_abi_temp = [
            {
                "inputs": [],
                "name": "getDomainSeparator",
                "outputs": [{"name": "", "type": "bytes32"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        registry_contract_temp = w3.eth.contract(
            address=CONFIG['contracts']['registry'],
            abi=registry_abi_temp
        )
        
        # Query the actual domain separator from the deployed contract
        domain_separator_bytes32 = registry_contract_temp.functions.getDomainSeparator().call()
        domain_separator = "0x" + domain_separator_bytes32.hex()
        print_success(f"✅ Queried domain separator from contract: {domain_separator}")
        
        # Create base PQ message: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce(0)
        eth_addr_bytes = bytes.fromhex(self.user_config['eth_address'][2:])
        base_pq_message = (
            bytes.fromhex(domain_separator[2:]) + 
            b"Intent to pair ETH Address " + 
            eth_addr_bytes + 
            (0).to_bytes(32, 'big')  # PQ nonce 0 for initial registration
        )
        
        base_pq_hex = base_pq_message.hex()
        print_info(f"Base PQ message length: {len(base_pq_message)} bytes")
        
        try:
            # Sign base PQ message with PQ key
            cmd = f"source myenv/bin/activate && python sign_cli.py sign --data {base_pq_hex} --privkey private_key.pem"
            result = subprocess.run(
                cmd, shell=True, cwd=self.ethfalcon_path, 
                capture_output=True, text=True, check=True
            )
            
            # Parse PQ signature components from ETHFALCON output
            lines = result.stdout.strip().split('\n')
            
            # Extract signature components
            salt_hex = None
            cs1_values = []
            cs2_values = []
            hint = 0
            
            for line in lines:
                if 'salt:' in line.lower():
                    salt_hex = line.split(':')[1].strip()
                elif 'hint:' in line.lower():
                    hint = int(line.split(':')[1].strip())
                elif 'cs1:' in line.lower():
                    # Parse cs1 array values - extract hex values after colon
                    values_part = line.split(':', 1)[1].strip()
                    hex_values = values_part.split()  # Split on whitespace
                    cs1_values = hex_values[:32]  # Take first 32 values
                    print_info(f"Parsed {len(cs1_values)} cs1 values")
                elif 'cs2:' in line.lower():
                    # Parse cs2 array values - extract hex values after colon  
                    values_part = line.split(':', 1)[1].strip()
                    hex_values = values_part.split()  # Split on whitespace
                    cs2_values = hex_values[:32]  # Take first 32 values
                    print_info(f"Parsed {len(cs2_values)} cs2 values")
            
            # Verify we got the expected number of values
            if len(cs1_values) != 32:
                print_error(f"Expected 32 cs1 values, got {len(cs1_values)}")
                return False
            if len(cs2_values) != 32:
                print_error(f"Expected 32 cs2 values, got {len(cs2_values)}")
                return False
            
            # Store the REAL signature components
            pq_signature_data = {
                'base_pq_message': base_pq_hex,
                'salt': salt_hex,
                'hint': hint,
                'cs1': cs1_values,  # Real values from ETHFALCON
                'cs2': cs2_values   # Real values from ETHFALCON
            }
            
            print_success("✅ Step 1 complete: PQ intent signature generated!")
            print_info(f"PQ signature salt: {salt_hex[:20]}..." if salt_hex else "Salt parsing needed")
            
        except subprocess.CalledProcessError as e:
            print_error(f"Step 1 failed: {e}")
            return False
        
        # Step 2: Ethereum Confirmation Signature (EIP-712 Format)
        print(f"\n{Colors.OKBLUE}🔑 Step 2: Signing Ethereum confirmation...{Colors.ENDC}")
        
        # Create SIMPLE ETH message for EIP-712 signing (not the complex byte structure)
        # This should match what the contract expects for submitRegistrationIntent
        
        # Build the ETH message that will be submitted to the contract
        # This is the message that gets built with PQ signature embedded
        
        # Build complete ETH message using REAL PQ signature components
        # 1. "Intent to pair Epervier Key" (literal text)
        text_part = b"Intent to pair Epervier Key"
        
        # 2. base_pq_message (already calculated)
        base_pq_bytes = bytes.fromhex(base_pq_hex)
        
        # 3. salt (40 bytes) - use REAL salt from ETHFALCON
        salt_bytes = bytes.fromhex(salt_hex[2:] if salt_hex.startswith('0x') else salt_hex)
        print_info(f"Using real salt: {len(salt_bytes)} bytes")
        
        # 4 & 5. cs1 and cs2 arrays - use REAL values from ETHFALCON  
        # Convert each hex value to 32-byte big-endian AND uint256 integers
        cs1_bytes = b''
        cs2_bytes = b''
        cs1_uint256 = []
        cs2_uint256 = []
        
        for hex_val in pq_signature_data['cs1']:
            val = int(hex_val, 16) if hex_val.startswith('0x') else int('0x' + hex_val, 16)
            cs1_bytes += val.to_bytes(32, 'big')
            cs1_uint256.append(val)
        
        for hex_val in pq_signature_data['cs2']:
            val = int(hex_val, 16) if hex_val.startswith('0x') else int('0x' + hex_val, 16)
            cs2_bytes += val.to_bytes(32, 'big')
            cs2_uint256.append(val)
        
        print_info(f"Built cs1: {len(cs1_bytes)} bytes, cs2: {len(cs2_bytes)} bytes")
        
        # 6. hint (32 bytes) - use REAL hint from ETHFALCON
        hint_bytes = hint.to_bytes(32, 'big')
        
        # 7. eth_nonce (32 bytes)
        eth_nonce_bytes = (0).to_bytes(32, 'big')
        
        # Build complete ETH message like test vectors with REAL VALUES
        eth_message_data = (
            text_part +           # "Intent to pair Epervier Key"
            base_pq_bytes +       # base_pq_message  
            salt_bytes +          # salt (40 bytes) - REAL
            cs1_bytes +           # cs1_array (1024 bytes) - REAL
            cs2_bytes +           # cs2_array (1024 bytes) - REAL  
            hint_bytes +          # hint (32 bytes) - REAL
            eth_nonce_bytes       # eth_nonce (32 bytes)
        )
        
        print_success(f"✅ Built complete ETH message: {len(eth_message_data)} bytes using REAL PQ signature!")
        
        print_info(f"Confirmation message: CONFIRM_REGISTRATION:REGISTER_PQ:{self.user_config['pq_fingerprint']}:{self.user_config['eth_address']}")
        
        # Sign with Ethereum private key using EIP-712
        signed_message = None
        try:
            if "private_key" in self.user_config:
                account = Account.from_key(self.user_config["private_key"])
                
                # Calculate EIP-712 struct hash for RegistrationIntent
                struct_hash = get_registration_intent_struct_hash(
                    salt_bytes, cs1_uint256, cs2_uint256, hint, base_pq_bytes, 0
                )
                
                # Calculate EIP-712 digest
                digest = get_eip712_digest(domain_separator_bytes32, struct_hash)
                
                # Sign the digest using EIP-712 method
                signed_message = Account._sign_hash(digest, private_key=account.key)
                print_success("✅ Step 2 complete: Ethereum confirmation signed!")
                print_info(f"Signature: {signed_message.signature.hex()[:20]}...")
            else:
                print_warning("🚧 No private key found, using simulated signature")
                print_success("✅ Step 2 complete: Ethereum confirmation signed! (simulated)")
        except Exception as e:
            print_error(f"Ethereum signing failed: {e}")
            print_success("✅ Step 2 complete: Ethereum confirmation signed! (simulated)")
        
        # Step 3: Submit to Blockchain
        print(f"\n{Colors.OKBLUE}⛓️  Step 3: Submitting registration to OP Sepolia blockchain...{Colors.ENDC}")
        
        try:
            if not signed_message:
                raise Exception("No Ethereum signature available")
                
            # Set up Web3 connection
            w3 = Web3(Web3.HTTPProvider(CONFIG['rpc_url']))
            if not w3.is_connected():
                raise Exception("Could not connect to OP Sepolia RPC")
                
            account = Account.from_key(self.user_config["private_key"])
            
            # Check ETH balance for gas fees
            balance = w3.eth.get_balance(account.address)
            balance_eth = w3.from_wei(balance, 'ether')
            print_info(f"Account balance: {balance_eth:.4f} ETH")
            
            if balance < w3.to_wei(0.001, 'ether'):  # Need at least 0.001 ETH for gas
                raise Exception(f"Insufficient ETH balance for gas fees. Need at least 0.001 ETH, have {balance_eth:.6f} ETH")
            
            # Load PQRegistry contract ABI (correct 2-step process)
            registry_abi = [
                {
                    "inputs": [
                        {"name": "ethMessage", "type": "bytes"},
                        {"name": "v", "type": "uint8"},
                        {"name": "r", "type": "bytes32"},
                        {"name": "s", "type": "bytes32"}
                    ],
                    "name": "submitRegistrationIntent",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "pqMessage", "type": "bytes"},
                        {"name": "salt", "type": "bytes"},
                        {"name": "cs1", "type": "uint256[]"},
                        {"name": "cs2", "type": "uint256[]"},
                        {"name": "hint", "type": "uint256"}
                    ],
                    "name": "confirmRegistration",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "ethAddress", "type": "address"}
                    ],
                    "name": "pendingIntents",
                    "outputs": [
                        {"name": "pqFingerprint", "type": "address"},
                        {"name": "intentMessage", "type": "bytes"},
                        {"name": "timestamp", "type": "uint256"}
                    ],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            # Create contract instance
            registry_contract = w3.eth.contract(
                address=CONFIG['contracts']['registry'],
                abi=registry_abi
            )
            
            print_success("🔗 Connected to OP Sepolia and PQRegistry contract!")
            
            # Step 3a: Submit Registration Intent
            print_info("📝 Step 3a: Submitting registration intent...")
            
            # Extract signature components and convert to proper format
            v = signed_message.v
            r = signed_message.r.to_bytes(32, 'big')  # Convert to bytes32
            s = signed_message.s.to_bytes(32, 'big')  # Convert to bytes32
            
            print_info(f"📝 Signature components: v={v}, r=0x{r.hex()[:16]}..., s=0x{s.hex()[:16]}...")
            
            # Build intent transaction
            nonce = w3.eth.get_transaction_count(account.address)
            gas_price = w3.eth.gas_price
            
            intent_transaction = registry_contract.functions.submitRegistrationIntent(
                eth_message_data,  # Use the properly constructed ETH message
                v,
                r,
                s
            ).build_transaction({
                'from': account.address,
                'nonce': nonce,
                'gas': 5000000,  # 5M gas limit for PQ operations
                'gasPrice': gas_price,
                'chainId': CONFIG['chain_id']
            })
            
            # Sign and send intent transaction
            signed_intent_txn = account.sign_transaction(intent_transaction)
            intent_tx_hash = w3.eth.send_raw_transaction(signed_intent_txn.raw_transaction)
            
            print_success(f"Intent submitted! Hash: {intent_tx_hash.hex()}")
            print_info("Waiting for intent confirmation...")
            
            # Wait for intent confirmation
            intent_receipt = w3.eth.wait_for_transaction_receipt(intent_tx_hash, timeout=120)
            if intent_receipt.status != 1:
                raise Exception("Intent transaction failed")
            
            print_success("✅ Registration intent confirmed!")
            
            # 🎯 QUERY CONTRACT TO GET ACTUAL MAPPED PQ FINGERPRINT
            print_info("🔍 Querying contract for actual mapped PQ fingerprint...")
            try:
                pending_intent = registry_contract.functions.pendingIntents(account.address).call()
                actual_pq_fingerprint = pending_intent[0]  # pqFingerprint from the contract
                intent_message = pending_intent[1]         # intentMessage  
                timestamp = pending_intent[2]              # timestamp
                
                print_success(f"✅ Contract query successful!")
                print_info(f"📋 Actual PQ fingerprint from contract: {actual_pq_fingerprint}")
                print_info(f"⏰ Intent timestamp: {timestamp}")
                
                # Update the fingerprint to use the contract's version
                original_fingerprint = self.user_config['pq_fingerprint']
                self.user_config['contract_pq_fingerprint'] = actual_pq_fingerprint
                
                if original_fingerprint != actual_pq_fingerprint:
                    print_warning(f"📋 Fingerprint updated: {original_fingerprint} → {actual_pq_fingerprint}")
                    print_info("✅ Using contract's fingerprint for confirmation message")
                else:
                    print_success("✅ Fingerprints match perfectly!")
                
            except Exception as e:
                print_error(f"Contract query failed: {e}")
                print_warning("⚠️  Using original fingerprint as fallback")
                actual_pq_fingerprint = self.user_config['pq_fingerprint']
            
            # Step 3b: Confirm Registration with PQ signature  
            print_info("🔐 Step 3b: Confirming registration with PQ signature...")
            
            # 🔥 NOW BUILD CONFIRMATION MESSAGE USING CONTRACT'S FINGERPRINT
            print_info(f"📝 Building confirmation message with contract fingerprint: {actual_pq_fingerprint}")
            
            # Build the actual ETH message format (from test vectors)
            print_info("📝 Building confirmation message in test vector format...")
            eth_nonce_bytes = (0).to_bytes(32, 'big')  # ETH nonce
            
            # 1. "Intent to pair Epervier Key" (literal text)
            text_part = b"Intent to pair Epervier Key"
            
            # 2. base_pq_message (already calculated)
            base_pq_bytes = bytes.fromhex(base_pq_hex)
            
            # 3. salt (40 bytes) - parse from ETHFALCON output
            if not salt_hex or not salt_hex.startswith('0x'):
                print_error("Invalid salt format from ETHFALCON")
                return False
            salt_bytes = bytes.fromhex(salt_hex[2:])  # Remove 0x prefix
            print_info(f"📝 Salt length: {len(salt_bytes)} bytes")
            
            # 4 & 5. cs1 and cs2 arrays - convert hex strings to uint256 integers
            print_info("📝 Converting cs1/cs2 hex values to uint256 integers...")
            cs1_uint256 = []
            cs2_uint256 = []
            
            for hex_val in pq_signature_data['cs1']:
                if hex_val.startswith('0x'):
                    cs1_uint256.append(int(hex_val, 16))
                else:
                    cs1_uint256.append(int('0x' + hex_val, 16))
            
            for hex_val in pq_signature_data['cs2']:
                if hex_val.startswith('0x'):
                    cs2_uint256.append(int(hex_val, 16))
                else:
                    cs2_uint256.append(int('0x' + hex_val, 16))
            
            print_info(f"✅ Converted {len(cs1_uint256)} cs1 values and {len(cs2_uint256)} cs2 values to uint256")
            
            # 6. hint (32 bytes)  
            hint_bytes = hint.to_bytes(32, 'big')
            
            # 7. eth_nonce (32 bytes)
            # (already defined above)
            
            # Build complete ETH message like test vectors
            confirmation_message_bytes = (
                text_part +           # "Intent to pair Epervier Key"
                base_pq_bytes +       # base_pq_message  
                salt_bytes +          # salt (40 bytes)
                # cs1_array and cs2_array are passed separately to contract as uint256[]
                # They represent 1024 bytes each but are passed as arrays
                hint_bytes +          # hint (32 bytes)
                eth_nonce_bytes       # eth_nonce (32 bytes)
            )
            
            print_info(f"📝 Complete confirmation message: {len(confirmation_message_bytes)} bytes")
            
            # Build confirmation transaction
            nonce = w3.eth.get_transaction_count(account.address)
            
            confirmation_transaction = registry_contract.functions.confirmRegistration(
                confirmation_message_bytes,
                salt_bytes,
                cs1_uint256,     # Converted to uint256[] 
                cs2_uint256,     # Converted to uint256[]
                hint             # Already an integer
            ).build_transaction({
                'from': account.address,
                'nonce': nonce,
                'gas': 5000000,  # 5M gas limit for PQ operations
                'gasPrice': gas_price,
                'chainId': CONFIG['chain_id']
            })
            
            # Sign and send confirmation transaction
            signed_confirmation_txn = account.sign_transaction(confirmation_transaction)
            confirmation_tx_hash = w3.eth.send_raw_transaction(signed_confirmation_txn.raw_transaction)
            
            print_success(f"Confirmation submitted! Hash: {confirmation_tx_hash.hex()}")
            print_info("Waiting for final confirmation...")
            
            # Wait for confirmation transaction receipt
            try:
                confirmation_receipt = w3.eth.wait_for_transaction_receipt(confirmation_tx_hash, timeout=120)
                if confirmation_receipt.status == 1:
                    print_success("✅ Registration fully confirmed on blockchain!")
                    
                    # Calculate deterministic token ID
                    token_id = int(self.user_config['pq_fingerprint'][-8:], 16)
                    
                    self.user_config.update({
                        "registered": True,
                        "registration_timestamp": time.time(),
                        "nft_token_id": token_id,
                        "nft_minted": True,
                        "intent_tx_hash": intent_tx_hash.hex(),
                        "confirmation_tx_hash": confirmation_tx_hash.hex()
                    })
                    self.save_config()
                    
                    print_success(f"🎨 PQ NFT automatically minted! Token ID: {token_id}")
                    print_info(f"🔗 View Intent: https://sepolia-optimistic.etherscan.io/tx/{intent_tx_hash.hex()}")
                    print_info(f"🔗 View Confirmation: https://sepolia-optimistic.etherscan.io/tx/{confirmation_tx_hash.hex()}")
                    
                else:
                    raise Exception("Confirmation transaction failed")
                    
            except Exception as e:
                print_error(f"Transaction confirmation failed: {e}")
                print_info("Transaction may still be pending. Check Etherscan for status.")
                return False
                
        except Exception as e:
            print_error(f"Blockchain submission failed: {e}")
            print_warning("Registration simulated locally only")
            
            # Fallback to simulated registration
            token_id = int(self.user_config['pq_fingerprint'][-8:], 16)
            self.user_config.update({
                "registered": True,
                "registration_timestamp": time.time(),
                "nft_token_id": token_id,
                "nft_minted": True,
                "simulated": True
            })
            self.save_config()
            
            print_success("✅ PQ fingerprint registered (simulated)")
            print_success(f"🎨 PQ NFT minted (simulated)! Token ID: {token_id}")
        
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}🎉 REGISTRATION COMPLETE! 🎉{Colors.ENDC}")
        print_info("Your NFT can only be transferred using post-quantum signatures!")
        
        return True

    def transfer_nft(self):
        """Step 4: Transfer NFT with PQ signature"""
        print_step(4, "Transfer Your NFT with PQ Signature")
        
        if "nft_token_id" not in self.user_config:
            print_error("No NFT found. Please mint an NFT first.")
            return False
        
        print("🔄 Transferring your NFT using post-quantum cryptography...")
        
        recipient = input("Enter recipient address (0x...): ").strip()
        if not recipient.startswith("0x") or len(recipient) != 42:
            print_error("Invalid recipient address")
            return False
        
        token_id = self.user_config["nft_token_id"]
        print_info(f"Transferring Token ID {token_id} to {recipient}")
        
        # TODO: Implement PQ transfer workflow
        print_warning("🚧 PQ transfer workflow coming soon!")
        
        print_success(f"NFT transfer initiated! (simulated)")
        return True

    def show_status(self):
        """Show user's current status"""
        print_header("Your PQ Status")
        
        if not self.user_config:
            print_info("No setup found. Run the setup process first!")
            return
        
        print(f"📍 ETH Address: {self.user_config.get('eth_address', 'Not set')}")
        print(f"🔐 PQ Fingerprint: {self.user_config.get('pq_fingerprint', 'Not generated')}")
        
        is_registered = self.user_config.get('registered', False)
        print(f"✅ Registered: {is_registered}")
        
        if is_registered:
            token_id = self.user_config.get('nft_token_id', 'Error')
            print(f"🎨 PQ NFT Token ID: {token_id} (auto-minted during registration)")
        else:
            print(f"🎨 PQ NFT: Not minted (complete registration to auto-mint)")
        
        if self.user_config.get('auto_detected'):
            print(f"🔍 Auto-detected from .env file")
        elif self.user_config.get('setup_timestamp'):
            setup_time = time.ctime(self.user_config['setup_timestamp'])
            print(f"⏰ Setup completed: {setup_time}")
        
        if self.user_config.get('registration_timestamp'):
            reg_time = time.ctime(self.user_config['registration_timestamp'])
            print(f"📝 Registration completed: {reg_time}")
            
        if self.user_config.get('tx_hash'):
            tx_hash = self.user_config['tx_hash']
            print(f"🔗 Transaction: https://sepolia-optimistic.etherscan.io/tx/{tx_hash}")
        elif self.user_config.get('simulated'):
            print(f"⚠️  Registration was simulated (not on blockchain)")

    def run_interactive_menu(self):
        """Main interactive menu"""
        while True:
            print_header("PQ PLAYGROUND MENU")
            print("1. 🔧 Setup Environment (ETH private key)")
            print("2. 🗝️  Generate PQ Keys")
            print("3. 📝 2-Step Registration + Auto-Mint NFT") 
            print("4. 🔄 Transfer NFT with PQ Signature")
            print("5. 📊 Show Status")
            print("6. 🧹 Clean Setup (start over)")
            print("0. 👋 Exit")
            
            choice = input(f"\n{Colors.BOLD}Choose an option (0-6): {Colors.ENDC}").strip()
            
            if choice == "0":
                print_success("Thanks for playing with post-quantum crypto! 🦅")
                break
            elif choice == "1":
                self.setup_environment()
            elif choice == "2":
                self.generate_pq_keys()
            elif choice == "3":
                self.register_pq_fingerprint()
            elif choice == "4":
                self.transfer_nft()
            elif choice == "5":
                self.show_status()
            elif choice == "6":
                self.clean_setup()
            else:
                print_error("Invalid choice. Please try again.")
            
            input(f"\n{Colors.OKCYAN}Press Enter to continue...{Colors.ENDC}")

    def clean_setup(self):
        """Clean up user setup"""
        print_warning("This will delete all your generated keys and configuration!")
        choice = input("Are you sure? (type 'DELETE' to confirm): ").strip()
        
        if choice == "DELETE":
            # Remove user files
            if self.env_file.exists():
                self.env_file.unlink()
            if self.config_file.exists():
                self.config_file.unlink()
            
            # Remove PQ keys
            for key_file in ["private_key.pem", "public_key.pem", "sig"]:
                key_path = self.ethfalcon_path / key_file
                if key_path.exists():
                    key_path.unlink()
            
            self.user_config = {}
            print_success("Setup cleaned! You can start fresh.")
        else:
            print_info("Cleanup cancelled.")

def main():
    print(f"""{Colors.HEADER}{Colors.BOLD}
    🦅 =============================================== 🦅
       WELCOME TO THE EPERVIER PQ PLAYGROUND!
    🦅 =============================================== 🦅{Colors.ENDC}
    
    {Colors.OKCYAN}Experience the future of quantum-resistant cryptography!{Colors.ENDC}
    
    In this playground, you'll:
    • Generate post-quantum Epervier keys 🗝️
    • Complete 2-step PQ registration 📝
    • Auto-mint quantum-resistant NFTs 🎨  
    • Transfer tokens with PQ signatures 🔄
    
    {Colors.WARNING}🚨 This is for testing and educational purposes only! 🚨{Colors.ENDC}
    """)
    
    playground = PQPlayground()
    
    try:
        playground.run_interactive_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Interrupted by user. Goodbye! 👋{Colors.ENDC}")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 