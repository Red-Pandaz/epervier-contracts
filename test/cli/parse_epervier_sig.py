import sys
import struct

# Usage: python parse_epervier_sig.py <sig_file>

if len(sys.argv) != 2:
    print("Usage: python parse_epervier_sig.py <sig_file>")
    sys.exit(1)

sig_path = sys.argv[1]

with open(sig_path, 'rb') as f:
    sig_bytes = f.read()

# Layout guess:
# [0]         1 byte   header
# [1:41]     40 bytes  salt
# [41:41+32*32]   cs1 (32 uint256, 32 bytes each)
# [..+32*32]  cs2 (32 uint256, 32 bytes each)
# [..+32]     hint (32 bytes)

header = sig_bytes[0]
salt = sig_bytes[1:41]
cs1_start = 41
cs1_end = cs1_start + 32*32
cs2_start = cs1_end
cs2_end = cs2_start + 32*32
hint_start = cs2_end
hint_end = hint_start + 32

cs1_bytes = sig_bytes[cs1_start:cs1_end]
cs2_bytes = sig_bytes[cs2_start:cs2_end]
hint_bytes = sig_bytes[hint_start:hint_end]

# Each cs1/cs2 element is 32 bytes (big endian uint256)
def bytes_to_uint256_arr(b):
    return [int.from_bytes(b[i*32:(i+1)*32], 'big') for i in range(32)]

cs1 = bytes_to_uint256_arr(cs1_bytes)
cs2 = bytes_to_uint256_arr(cs2_bytes)
hint = int.from_bytes(hint_bytes, 'big')

print(f"Header: {header}")
print(f"Salt (hex): {salt.hex()}")
print(f"cs1: {[hex(x) for x in cs1]}")
print(f"cs2: {[hex(x) for x in cs2]}")
print(f"Hint: {hex(hint)}")

# For contract input, print as Python literals
print("\n--- Contract Input ---")
print(f"salt = bytes.fromhex('{salt.hex()}' )")
print(f"cs1 = {cs1}")
print(f"cs2 = {cs2}")
print(f"hint = {hint}") 