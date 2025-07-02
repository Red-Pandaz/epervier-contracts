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
REGISTRATION_INTENT_TYPE_HASH = "0x6c82d11868bb07b09942f187a0411348a333edceb605e23f50498111c090e8cd"
REGISTRATION_CONFIRMATION_TYPE_HASH = "0x18de7768ef44f4d9fc06fe05870b6e013cdefc55ac93a9ba5ecc3bcdbe73c57f"
REMOVE_INTENT_TYPE_HASH = "0xeabb87d4659aa065c1553e7f5514018dede42e554eee09f74b28dcaa233ecc8e"
CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH = "0xb8e7209f5412776d3e03646b038b4192bba4cdc7ad3ab72889d80f723977f22a"
CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH = "0x0da348aa682da5451c21b5d7d27193b16bc590e19ad83d5ea79b6c66e127e22c"
UNREGISTRATION_INTENT_TYPE_HASH = "0x09b4a42af98d1139e6cd5eae85587da9f5eb0f7f5b31bf66989d66a0b25ebbb0"
UNREGISTRATION_CONFIRMATION_TYPE_HASH = "0xd5abe80eec8c24c1e5bd8472f82ed805597b716f6440bc704d83e23ad0226fbf"
REMOVE_CHANGE_INTENT_TYPE_HASH = "0x4f972ac795959e01935c69784908f945291fb93578f26cdf08d85af2843915d4"

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