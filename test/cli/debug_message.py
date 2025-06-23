#!/usr/bin/env python3

import hashlib

# Python version
domain_separator = bytes.fromhex("6e6211dbff87ae7e18ea41be423eb6095e1ad79ac80e24581c59e888c4a83dda")
message_part = b"Intent to pair Epervier Key"
nonce_bytes = (0).to_bytes(32, byteorder="big")
eth_intent_message = domain_separator + message_part + nonce_bytes

print("Python bytes (hex):", eth_intent_message.hex())
print("Python bytes length:", len(eth_intent_message))

# Let's also check what keccak256("PQRegistry") should be
domain_check = hashlib.sha3_256(b"PQRegistry").digest()
print("keccak256('PQRegistry') (hex):", domain_check.hex())
print("Domain separator from contract (hex):", domain_separator.hex())
print("Match:", domain_check == domain_separator)

# Let's also check the individual components
print("\nComponents:")
print("Domain separator (32 bytes):", domain_separator.hex())
print("Message part (23 bytes):", message_part.hex())
print("Nonce (32 bytes):", nonce_bytes.hex()) 