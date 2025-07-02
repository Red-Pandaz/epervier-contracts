#!/usr/bin/env python3

def parse_eth_unregistration_confirmation_message(message_hex):
    """
    Parse ETH unregistration confirmation message using the same offsets as the Solidity contract
    """
    message = bytes.fromhex(message_hex)
    
    # Offsets and lengths from the contract
    pattern_offset = 0
    pattern_length = 49
    
    pq_fingerprint_offset = 49
    pq_fingerprint_length = 20
    
    base_pq_message_offset = 69
    base_pq_message_length = 124
    
    salt_offset = 193
    salt_length = 40
    
    cs1_offset = 233
    cs1_length = 1024
    
    cs2_offset = 1257
    cs2_length = 1024
    
    hint_offset = 2281
    hint_length = 32
    
    eth_nonce_offset = 2313
    eth_nonce_length = 32
    
    print(f"Message length: {len(message)} bytes")
    print(f"Expected total length: 2375 bytes")
    
    # Extract fields
    pattern = message[pattern_offset:pattern_offset + pattern_length]
    pq_fingerprint = message[pq_fingerprint_offset:pq_fingerprint_offset + pq_fingerprint_length]
    base_pq_message = message[base_pq_message_offset:base_pq_message_offset + base_pq_message_length]
    salt = message[salt_offset:salt_offset + salt_length]
    cs1_bytes = message[cs1_offset:cs1_offset + cs1_length]
    cs2_bytes = message[cs2_offset:cs2_offset + cs2_length]
    hint_bytes = message[hint_offset:hint_offset + hint_length]
    eth_nonce_bytes = message[eth_nonce_offset:eth_nonce_offset + eth_nonce_length]
    
    # Convert to appropriate types
    def bytes_to_uint256_array(bytes_data):
        """Convert 1024 bytes to 32 uint256 values (32 bytes each)"""
        result = []
        for i in range(32):
            start = i * 32
            end = start + 32
            uint256_bytes = bytes_data[start:end]
            value = int.from_bytes(uint256_bytes, 'big')
            result.append(value)
        return result
    
    def bytes_to_uint256(bytes_data):
        """Convert 32 bytes to uint256"""
        return int.from_bytes(bytes_data, 'big')
    
    cs1 = bytes_to_uint256_array(cs1_bytes)
    cs2 = bytes_to_uint256_array(cs2_bytes)
    hint = bytes_to_uint256(hint_bytes)
    eth_nonce = bytes_to_uint256(eth_nonce_bytes)
    
    print("\n=== Parsed Fields ===")
    print(f"pattern: {pattern.hex()}")
    print(f"pqFingerprint: {pq_fingerprint.hex()}")
    print(f"basePQMessage: {base_pq_message.hex()}")
    print(f"salt: {salt.hex()}")
    print(f"hint: {hint}")
    print(f"ethNonce: {eth_nonce}")
    print(f"cs1[0]: {cs1[0]}")
    print(f"cs1[1]: {cs1[1]}")
    print(f"cs2[0]: {cs2[0]}")
    print(f"cs2[1]: {cs2[1]}")
    
    return {
        'pattern': pattern,
        'pqFingerprint': pq_fingerprint,
        'basePQMessage': base_pq_message,
        'salt': salt,
        'cs1': cs1,
        'cs2': cs2,
        'hint': hint,
        'ethNonce': eth_nonce
    }

if __name__ == "__main__":
    # You can paste the ETH message hex here from the Python generator output
    # Example: message_hex = "436f6e6669726d20756e726567697374726174696f6e2066726f6d2045706572766965722046696e6765727072696e74207b317f4d231cbc63de7c6c690ef4ba9c653437fb..."
    
    print("Paste the ETH confirmation message hex from the Python generator output:")
    message_hex = input().strip()
    
    if message_hex.startswith("0x"):
        message_hex = message_hex[2:]
    
    try:
        parsed = parse_eth_unregistration_confirmation_message(message_hex)
        print("\n=== Comparison ===")
        print("Compare these values with the Solidity contract logs to find the mismatch.")
    except Exception as e:
        print(f"Error parsing message: {e}") 