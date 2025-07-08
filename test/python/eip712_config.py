# EIP712 Domain Separator Configuration
# This file contains the domain separator values used for EIP712 structured signing

# Domain parameters
DOMAIN_NAME = "PQRegistry"
DOMAIN_VERSION = "1"
CHAIN_ID = 11155420
CONTRACT_ADDRESS = "0x0000000000000000000000000000000000000000"  # Will be updated when deployed

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

# Hardcoded domain separator for vector generation
# This should match what the contract computes in its constructor
# For testing, we'll use a fixed contract address
TEST_CONTRACT_ADDRESS = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"

# The domain separator is computed as:
# keccak256(abi.encode(
#     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
#     keccak256(bytes(DOMAIN_NAME)),
#     keccak256(bytes(DOMAIN_VERSION)),
#     CHAIN_ID,
#     TEST_CONTRACT_ADDRESS
# ))

# This is the precomputed value for the test environment
DOMAIN_SEPARATOR = "0x07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92"

# Note: The actual DOMAIN_SEPARATOR will be computed in the contract as:
# keccak256(abi.encode(
#     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
#     keccak256(bytes(DOMAIN_NAME)),
#     keccak256(bytes(DOMAIN_VERSION)),
#     CHAIN_ID,
#     address(this)
# )) 

# PQERC721 Transfer domain separator (keccak256("PQERC721 Transfer"))
PQERC721_TRANSFER_DOMAIN_SEPARATOR = "0xf5514acfa26be825f841b1d19d3b102fc708b67a0f729c16164a24d825356df0" 