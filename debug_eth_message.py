#!/usr/bin/env python3
import json

# Load the test vector
with open('test/test_vectors/comprehensive_vector_1.json', 'r') as f:
    data = json.load(f)

# Extract the pq_confirm_message
pq_confirm_message_hex = data['registration']['pq_confirm_message']
pq_confirm_message = bytes.fromhex(pq_confirm_message_hex)

print(f"PQ confirm message length: {len(pq_confirm_message)} bytes")
print(f"PQ confirm message (hex): {pq_confirm_message_hex}")

# Extract the ETH message from the PQ confirm message
# Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
eth_message_start = 32 + 27 + 20 + 32 + 65  # DOMAIN_SEPARATOR + pattern + address + pqNonce + ethSignature
eth_message = pq_confirm_message[eth_message_start:]

print(f"\nETH message length: {len(eth_message)} bytes")
print(f"ETH message (hex): {eth_message.hex()}")

# Print bytes at offsets 32-100 to see the pattern
print(f"\nBytes at offsets 32-100:")
for i in range(32, min(101, len(eth_message))):
    byte_val = eth_message[i]
    ascii_char = chr(byte_val) if 32 <= byte_val <= 126 else '.'
    print(f"Offset {i:2d}: {byte_val:3d} (0x{byte_val:02x}) '{ascii_char}'")

# Check different pattern lengths
for pattern_length in [34, 35, 36, 37, 38]:
    print(f"\n=== Testing pattern length {pattern_length} ===")
    fingerprint_start = 32 + pattern_length
    fingerprint_end = fingerprint_start + 32
    
    if fingerprint_end <= len(eth_message):
        fingerprint_bytes = eth_message[fingerprint_start:fingerprint_end]
        print(f"Fingerprint bytes ({fingerprint_start}-{fingerprint_end-1}): {fingerprint_bytes.hex()}")
        
        # Convert to address and then to bytes32
        extracted_address = int.from_bytes(fingerprint_bytes, 'big')
        address_from_bytes = extracted_address & 0xffffffffffffffffffffffffffffffffffffffff  # Take last 20 bytes
        bytes32_from_address = address_from_bytes << 96  # Left-pad to 32 bytes
        
        expected_fingerprint = 0x0000000000000000000000007b317f4d231cbc63de7c6c690ef4ba9c653437fb
        print(f"Extracted bytes32: {bytes32_from_address}")
        print(f"Expected bytes32:  {expected_fingerprint}")
        print(f"Match: {bytes32_from_address == expected_fingerprint}")
        
        if bytes32_from_address == expected_fingerprint:
            print(f"*** CORRECT PATTERN LENGTH FOUND: {pattern_length} ***")
            break

# Check the pattern "Confirm bonding to epervier fingerprint "
print(f"\nPattern analysis:")
pattern_start = 32
pattern_end = 32 + 36
pattern_bytes = eth_message[pattern_start:pattern_end]
pattern_ascii = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in pattern_bytes)
print(f"Pattern bytes (32-67): {pattern_bytes.hex()}")
print(f"Pattern ASCII: '{pattern_ascii}'")
print(f"Pattern length: {len(pattern_bytes)} bytes")

# Check the fingerprint bytes (should start at offset 68)
print(f"\nFingerprint analysis:")
fingerprint_start = 68
fingerprint_end = 68 + 32
fingerprint_bytes = eth_message[fingerprint_start:fingerprint_end]
print(f"Fingerprint bytes (68-99): {fingerprint_bytes.hex()}")
print(f"Expected fingerprint: 0000000000000000000000007b317f4d231cbc63de7c6c690ef4ba9c653437fb")

# Check the nonce bytes (should be at the end)
print(f"\nNonce analysis:")
nonce_start = len(eth_message) - 32
nonce_bytes = eth_message[nonce_start:]
nonce_value = int.from_bytes(nonce_bytes, 'big')
print(f"Nonce bytes (last 32): {nonce_bytes.hex()}")
print(f"Nonce value: {nonce_value}") 