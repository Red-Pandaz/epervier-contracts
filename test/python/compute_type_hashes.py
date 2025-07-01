#!/usr/bin/env python3
"""
Script to compute EIP712 type hashes for the PQRegistry contract
"""

import hashlib

def keccak256(data):
    """Compute keccak256 hash of data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha3_256(data).hexdigest()

# Type strings from the contract
type_strings = [
    "RegistrationIntent(uint256 ethNonce,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage)",
    "RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)",
    "RemoveIntent(address pqFingerprint,uint256 ethNonce)",
    "ChangeETHAddressIntent(address newETHAddress,uint256 ethNonce)",
    "ChangeETHAddressConfirmation(address oldETHAddress,uint256 ethNonce)",
    "UnregistrationIntent(uint256 ethNonce)",
    "UnregistrationConfirmation(address pqFingerprint,uint256 ethNonce)",
    "RemoveChangeIntent(uint256 ethNonce)"
]

# Type hash names
type_names = [
    "REGISTRATION_INTENT_TYPE_HASH",
    "REGISTRATION_CONFIRMATION_TYPE_HASH", 
    "REMOVE_INTENT_TYPE_HASH",
    "CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH",
    "CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH",
    "UNREGISTRATION_INTENT_TYPE_HASH",
    "UNREGISTRATION_CONFIRMATION_TYPE_HASH",
    "REMOVE_CHANGE_INTENT_TYPE_HASH"
]

print("EIP712 Type Hashes:")
print("=" * 50)

for i, (name, type_str) in enumerate(zip(type_names, type_strings)):
    hash_value = keccak256(type_str)
    print(f'{name} = "0x{hash_value}"')
    
print("\nCopy these values to eip712_config.py") 