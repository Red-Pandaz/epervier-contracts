# Production EIP-712 configuration for testing
# This file contains the domain separator and contract address for the production deployment

# Contract address from the latest deployment
CONTRACT_ADDRESS = "0x18e3bc34fc2645bdce2b85af6f9e0ac3cd26637e"  # OP Sepolia deployment

# Domain separator for the production contract
# This is computed as: keccak256(abi.encode(
#     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
#     keccak256(bytes("PQRegistry")),
#     keccak256(bytes("1")),
#     chainId,
#     contractAddress
# ))
DOMAIN_SEPARATOR = "0x2ac7a47e193e1f990b3314176f1b025264d962bc8cc6cf4c829c9d9fa6cb5ea8"

# Chain ID for OP Sepolia
CHAIN_ID = 11155420

# Contract name and version
CONTRACT_NAME = "PQRegistry"
CONTRACT_VERSION = "1"

# Production contract address (same as above, but with different name for clarity)
PRODUCTION_CONTRACT_ADDRESS = "0x18e3bc34fc2645bdce2b85af6f9e0ac3cd26637e"

# EIP712 Domain Separator Type Hash
DOMAIN_SEPARATOR_TYPE_HASH = "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"

# EIP712 Type Hashes (matching the contract)
REGISTRATION_INTENT_TYPE_HASH = "0x9769cf982eace30c9b9539ef87f8586301e22aec70b6d22e7f52b01ec6c9a062"
REGISTRATION_CONFIRMATION_TYPE_HASH = "0x18de7768ef44f4d9fc06fe05870b6e013cdefc55ac93a9ba5ecc3bcdbe73c57f"
REMOVE_INTENT_TYPE_HASH = "0xeabb87d4659aa065c1553e7f5514018dede42e554eee09f74b28dcaa233ecc8e"
CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH = "0x8441e90266f48d33a5a1260709abba24b3430e47ab3d82adce0b004adfd6af56"
CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH = "0xef103f9287de2614d209a17effc1fca3850c38da6e1988df36bcd072098f053d"
UNREGISTRATION_INTENT_TYPE_HASH = "0x4a02f0938628e11b00b4389b404d4fa42410d6ed8c7bd0c53f03540d19016917"
UNREGISTRATION_CONFIRMATION_TYPE_HASH = "0xe1842b7cdd493617ace7a90fddb453878fb3c0a49d6d4ddc42b3053e550d6572"
REMOVE_CHANGE_INTENT_TYPE_HASH = "0x8a4219708f845ffad56de1e9c69d5ef78efd1d577a9e69d4c115cd97a0ed576b"
REMOVE_UNREGISTRATION_INTENT_TYPE_HASH = "0x40735759c17eacbf91cffbb1dcd8535800fffaf989b7a2a7200e3171769a7e90"

# PQERC721 Transfer domain separator (keccak256("PQERC721 Transfer"))
PQERC721_TRANSFER_DOMAIN_SEPARATOR = "0xf5514acfa26be825f841b1d19d3b102fc708b67a0f729c16164a24d825356df0"

# Network and deployment configuration
RPC_URL = "https://sepolia.optimism.io"
DEPLOYER_ADDRESS = "0xc956cb7a8a9fc7e1fa52d7e8cdbc0ce0c8b8f633"
DEPLOYER_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
PQ_REGISTRY_ADDRESS = PRODUCTION_CONTRACT_ADDRESS 