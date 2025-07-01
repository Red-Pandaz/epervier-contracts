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
REGISTRATION_CONFIRMATION_TYPE_HASH = "0x9c72408f08e33645658a3082401bcabbd0d3803d0e7bd4e7ccd1ba31dc355e42"
REMOVE_INTENT_TYPE_HASH = "0x7787773e4cdf380124e8392841703d948b9cc8f1c7305ecf19c34dffdb449dbf"
CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH = "0xad9c7fd98278e0491b4ce426e94e536f62add607a7f807ffdf38be3a091083ba"
CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH = "0xda30aa3205452341590172cf23b24acb65901330ccc9b39d7ab09e2655e77ab4"
UNREGISTRATION_INTENT_TYPE_HASH = "0x3dff1ea3007a7dce6fd087cada5bc6a2536df49ff71603b8bbb5a455a38a696c"
UNREGISTRATION_CONFIRMATION_TYPE_HASH = "0xf46f8261cd17c25e9128d0041059f670d1965f2387117dc4ac34542b3028da56"
REMOVE_CHANGE_INTENT_TYPE_HASH = "0xd5374f2c763a462fe47bd1d024c2cf59b3ee1ec6126bb83be1f1fda1562a50eb"
REMOVE_UNREGISTRATION_INTENT_TYPE_HASH = "0x1234567890123456789012345678901234567890123456789012345678901234"  # Placeholder

# Hardcoded domain separator for vector generation (will be updated before deployment)
# This should match what the contract computes in its constructor
DOMAIN_SEPARATOR = "0x1234567890123456789012345678901234567890123456789012345678901234"  # Placeholder

# Note: The actual DOMAIN_SEPARATOR will be computed in the contract as:
# keccak256(abi.encode(
#     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
#     keccak256(bytes(DOMAIN_NAME)),
#     keccak256(bytes(DOMAIN_VERSION)),
#     CHAIN_ID,
#     address(this)
# )) 