#!/usr/bin/env python3
"""
Compute the domain separator for the deployed PQRegistry contract
"""

from eth_utils import keccak
from eth_abi.packed import encode_packed

def compute_domain_separator(contract_address, chain_id=31337):
    """Compute the EIP-712 domain separator for PQRegistry"""
    
    # Domain parameters
    domain_name = "PQRegistry"
    domain_version = "1"
    
    # EIP-712 Domain Separator Type Hash
    domain_separator_type_hash = keccak(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    
    # Compute the domain separator
    domain_separator = keccak(encode_packed(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [domain_separator_type_hash, keccak(domain_name.encode()), keccak(domain_version.encode()), chain_id, contract_address]
    ))
    
    return domain_separator

def main():
    # Production contract address from deployment
    contract_address = "0x68B1D87F95878fE05B998F19b66F4baba5De1aed"
    chain_id = 31337  # Local devnet
    
    print("Computing domain separator for PQRegistry...")
    print(f"Contract address: {contract_address}")
    print(f"Chain ID: {chain_id}")
    
    domain_separator = compute_domain_separator(contract_address, chain_id)
    
    print(f"\nDomain Separator: {domain_separator.hex()}")
    print(f"Domain Separator (with 0x): 0x{domain_separator.hex()}")
    
    print("\nUpdate the production_eip712_config.py with this value:")
    print(f'DOMAIN_SEPARATOR = "0x{domain_separator.hex()}"')

if __name__ == "__main__":
    main() 