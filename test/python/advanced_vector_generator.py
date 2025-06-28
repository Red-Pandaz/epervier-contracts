#!/usr/bin/env python3
"""
Advanced Vector Generator for PQRegistry Testing

This generator can create test vectors with custom nonces for advanced testing scenarios.
It extends the basic generator to support:
- Custom nonce values
- Multiple actors with different nonces
- Complex state transition scenarios
"""

import json
import os
import sys
from typing import Dict, List, Any, Optional
from web3 import Web3
from eth_account import Account
import secrets

# Change the import to reference the local file directly
from generate_test_vectors import (
    DOMAIN_SEPARATOR, 
    generate_epervier_signature,  # This is the actual function name
    ACTORS_CONFIG,  # Add this to get actor config
    abi_encode_packed,  # Add this for message creation
    pack_uint256_array  # Add this for array packing
)

def generate_eth_signature(message, private_key):
    """Generate ETH signature for a message"""
    from eth_account import Account
    from eth_hash.auto import keccak
    
    account = Account.from_key(private_key)
    message_length = len(message)
    signed_message = b"\x19Ethereum Signed Message:\n" + str(message_length).encode() + message
    message_hash = keccak(signed_message)
    signature = Account._sign_hash(message_hash, private_key=account.key)
    
    return {
        "v": signature.v,
        "r": signature.r,
        "s": signature.s
    }

def create_base_pq_registration_intent_message(eth_address, pq_nonce):
    """Create base PQ registration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_registration_intent_message(base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Create ETH registration intent message"""
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        base_pq_message,
        bytes.fromhex(salt[2:]) if isinstance(salt, str) else salt,
        pack_uint256_array(cs1),
        pack_uint256_array(cs2),
        hint.to_bytes(32, 'big'),
        eth_nonce.to_bytes(32, 'big')
    )

def create_eth_remove_registration_intent_message(pq_fingerprint, eth_nonce):
    """Create ETH remove registration intent message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Remove registration intent from Epervier fingerprint ",
        pq_fingerprint_bytes,
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_remove_registration_intent_message(eth_address, pq_nonce):
    """Create PQ remove registration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Remove registration intent from ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_remove_change_intent_message(pq_fingerprint, eth_nonce):
    """Create ETH remove change intent message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Remove change intent from address",
        pq_fingerprint_bytes,
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_remove_change_intent_message(eth_address, pq_nonce):
    """Create PQ remove change intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Remove change intent from address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_pq_remove_unregistration_intent_message(eth_address, pq_nonce):
    """Create PQ remove unregistration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Remove unregistration intent from address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_eth_registration_confirmation_message(pq_fingerprint, eth_nonce):
    """Create base ETH registration confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm bonding to Epervier fingerprint ",
        pq_fingerprint_bytes,
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_registration_confirmation_message(eth_address, base_eth_message, v, r, s, pq_nonce):
    """Create PQ registration confirmation message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm binding ETH Address ",
        eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_eth_change_eth_address_intent_message(pq_fingerprint, new_eth_address, eth_nonce):
    """Create base ETH change ETH address intent message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to change ETH Address and bond with Epervier fingerprint ",
        pq_fingerprint_bytes,
        " to ",
        new_eth_address_bytes,
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_change_eth_address_intent_message(old_eth_address, new_eth_address, base_eth_message, v, r, s, pq_nonce):
    """Create PQ change ETH address intent message"""
    old_eth_address_bytes = bytes.fromhex(old_eth_address[2:])  # Remove 0x prefix
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to change bound ETH Address from ",
        old_eth_address_bytes,
        " to ",
        new_eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_pq_change_eth_address_confirm_message(old_eth_address, new_eth_address, pq_nonce):
    """Create base PQ change ETH address confirm message"""
    old_eth_address_bytes = bytes.fromhex(old_eth_address[2:])  # Remove 0x prefix
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm changing bound ETH Address for Epervier fingerprint from ",
        old_eth_address_bytes,
        " to ",
        new_eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_change_eth_address_confirmation_message(pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Create ETH change ETH address confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm change ETH Address for Epervier fingerprint ",
        pq_fingerprint_bytes,
        base_pq_message,
        bytes.fromhex(salt[2:]) if isinstance(salt, str) else salt,
        pack_uint256_array(cs1),
        pack_uint256_array(cs2),
        hint.to_bytes(32, 'big'),
        eth_nonce.to_bytes(32, 'big')
    )

def create_base_eth_unregistration_intent_message(pq_fingerprint, eth_nonce):
    """Create base ETH unregistration intent message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to unregister from Epervier fingerprint ",
        pq_fingerprint_bytes,
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_unregistration_intent_message(current_eth_address, base_eth_message, v, r, s, pq_nonce):
    """Create PQ unregistration intent message"""
    current_eth_address_bytes = bytes.fromhex(current_eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to unregister from Epervier fingerprint from address ",
        current_eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_pq_unregistration_confirm_message(eth_address, pq_nonce):
    """Create base PQ unregistration confirm message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm unregistration from ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_unregistration_confirmation_message(pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Create ETH unregistration confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm unregistration from Epervier fingerprint ",
        pq_fingerprint_bytes,
        base_pq_message,
        bytes.fromhex(salt[2:]) if isinstance(salt, str) else salt,
        pack_uint256_array(cs1),
        pack_uint256_array(cs2),
        hint.to_bytes(32, 'big'),
        eth_nonce.to_bytes(32, 'big')
    )

class AdvancedVectorGenerator:
    def __init__(self):
        self.w3 = Web3()
        self.account = Account()
        
        # Use the centralized actor configuration
        self.actors = ACTORS_CONFIG
    
    def generate_registration_intent_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base PQ message
        base_pq_message = create_base_pq_registration_intent_message(
            actor_data["eth_address"], 
            pq_nonce
        )
        
        # Generate PQ signature using the CLI
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Convert cs1 and cs2 to hex strings like the working vectors
        cs1_hex = [f"0x{x:064x}" for x in pq_signature["cs1"]]
        cs2_hex = [f"0x{x:064x}" for x in pq_signature["cs2"]]
        
        # Create ETH message
        eth_message = create_eth_registration_intent_message(
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],  # Use original integers for packing
            pq_signature["cs2"],  # Use original integers for packing
            pq_signature["hint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = generate_eth_signature(eth_message, actor_data["eth_private_key"])
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_signature["salt"],
                "cs1": cs1_hex,
                "cs2": cs2_hex,
                "hint": pq_signature["hint"],
                "raw_signature": pq_signature["raw_signature"]
            },
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_registration_confirmation_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration confirmation vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base ETH confirmation message
        base_eth_message = create_base_eth_registration_confirmation_message(
            actor_data["pq_fingerprint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = generate_eth_signature(base_eth_message, actor_data["eth_private_key"])
        
        # Create PQ confirmation message
        pq_message = create_pq_registration_confirmation_message(
            actor_data["eth_address"],
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(pq_message, actor)
        
        # Convert cs1 and cs2 to hex strings like the working vectors
        cs1_hex = [f"0x{x:064x}" for x in pq_signature["cs1"]]
        cs2_hex = [f"0x{x:064x}" for x in pq_signature["cs2"]]
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_signature["salt"],
                "cs1": cs1_hex,
                "cs2": cs2_hex,
                "hint": pq_signature["hint"],
                "raw_signature": pq_signature["raw_signature"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_change_eth_address_intent_vector(self, actor: str, new_eth_address: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a change ETH address intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base ETH change intent message
        base_eth_message = create_base_eth_change_eth_address_intent_message(
            actor_data["pq_fingerprint"],
            new_eth_address,
            eth_nonce
        )
        
        # Generate ETH signature using the new ETH address's private key
        # For testing, we'll use a deterministic private key based on the new address
        from eth_account import Account
        new_account = Account.create()  # Create a new account for the new ETH address
        eth_signature = generate_eth_signature(base_eth_message, new_account.key)
        
        # Create PQ change intent message
        pq_message = create_pq_change_eth_address_intent_message(
            actor_data["eth_address"],
            new_eth_address,
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(pq_message, actor)
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "new_eth_address": new_eth_address,
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_change_eth_address_confirmation_vector(self, actor: str, new_eth_address: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a change ETH address confirmation vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base PQ change confirmation message
        base_pq_message = create_base_pq_change_eth_address_confirm_message(
            actor_data["eth_address"],
            new_eth_address,
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Create ETH confirmation message
        eth_message = create_eth_change_eth_address_confirmation_message(
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )
        
        # Generate ETH signature using the new ETH address's private key
        # For testing, we'll use a deterministic private key based on the new address
        from eth_account import Account
        new_account = Account.create()  # Create a new account for the new ETH address
        eth_signature = generate_eth_signature(eth_message, new_account.key)
        
        return {
            "actor": actor,
            "old_eth_address": actor_data["eth_address"],
            "new_eth_address": new_eth_address,
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_unregistration_intent_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate an unregistration intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base ETH unregistration intent message
        base_eth_message = create_base_eth_unregistration_intent_message(
            actor_data["pq_fingerprint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = generate_eth_signature(base_eth_message, actor_data["eth_private_key"])
        
        # Create PQ unregistration intent message
        pq_message = create_pq_unregistration_intent_message(
            actor_data["eth_address"],
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(pq_message, actor)
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_unregistration_confirmation_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate an unregistration confirmation vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base PQ unregistration confirmation message
        base_pq_message = create_base_pq_unregistration_confirm_message(
            actor_data["eth_address"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Create ETH confirmation message
        eth_message = create_eth_unregistration_confirmation_message(
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = generate_eth_signature(eth_message, actor_data["eth_private_key"])
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_removal_vector(self, actor: str, removal_type: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a removal vector with custom nonces"""
        actor_data = self.actors[actor]
        
        if removal_type == "registration_eth":
            message = create_eth_remove_registration_intent_message(
                actor_data["pq_fingerprint"],
                eth_nonce
            )
            signature = generate_eth_signature(message, actor_data["eth_private_key"])
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "eth_message": message.hex(),
                "eth_signature": signature,
                "eth_nonce": eth_nonce
            }
        
        elif removal_type == "registration_pq":
            message = create_pq_remove_registration_intent_message(
                actor_data["eth_address"],
                pq_nonce
            )
            signature = generate_epervier_signature(message, actor)
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "pq_message": message.hex(),
                "pq_signature": signature,
                "pq_nonce": pq_nonce
            }
        
        elif removal_type == "change_eth":
            message = create_eth_remove_change_intent_message(
                actor_data["pq_fingerprint"],
                eth_nonce
            )
            signature = generate_eth_signature(message, actor_data["eth_private_key"])
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "eth_message": message.hex(),
                "eth_signature": signature,
                "eth_nonce": eth_nonce
            }
        
        elif removal_type == "change_pq":
            message = create_pq_remove_change_intent_message(
                actor_data["eth_address"],
                pq_nonce
            )
            signature = generate_epervier_signature(message, actor)
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "pq_message": message.hex(),
                "pq_signature": signature,
                "pq_nonce": pq_nonce
            }
        
        elif removal_type == "unregistration_pq":
            message = create_pq_remove_unregistration_intent_message(
                actor_data["eth_address"],
                pq_nonce
            )
            signature = generate_epervier_signature(message, actor)
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "pq_message": message.hex(),
                "pq_signature": signature,
                "pq_nonce": pq_nonce
            }
        
        else:
            raise ValueError(f"Unknown removal type: {removal_type}")
    
    def generate_scenario_vectors(self, scenario_name: str, scenario_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate vectors for a complete test scenario"""
        vectors = {
            "scenario_name": scenario_name,
            "vectors": []
        }
        
        for step in scenario_config["steps"]:
            step_type = step["type"]
            actor = step["actor"]
            eth_nonce = step.get("eth_nonce", 0)
            pq_nonce = step.get("pq_nonce", 0)
            
            if step_type == "registration_intent":
                vector = self.generate_registration_intent_vector(actor, eth_nonce, pq_nonce)
            elif step_type == "registration_confirmation":
                vector = self.generate_registration_confirmation_vector(actor, eth_nonce, pq_nonce)
            elif step_type == "change_eth_intent":
                new_eth_address = step["new_eth_address"]
                vector = self.generate_change_eth_address_intent_vector(actor, new_eth_address, eth_nonce, pq_nonce)
            elif step_type == "change_eth_confirmation":
                new_eth_address = step["new_eth_address"]
                vector = self.generate_change_eth_address_confirmation_vector(actor, new_eth_address, eth_nonce, pq_nonce)
            elif step_type == "unregistration_intent":
                vector = self.generate_unregistration_intent_vector(actor, eth_nonce, pq_nonce)
            elif step_type == "unregistration_confirmation":
                vector = self.generate_unregistration_confirmation_vector(actor, eth_nonce, pq_nonce)
            elif step_type.startswith("removal_"):
                removal_type = step_type.replace("removal_", "")
                vector = self.generate_removal_vector(actor, removal_type, eth_nonce, pq_nonce)
            else:
                raise ValueError(f"Unknown step type: {step_type}")
            
            vector["step_type"] = step_type
            vector["step_order"] = step.get("order", len(vectors["vectors"]))
            vectors["vectors"].append(vector)
        
        return vectors

def main():
    """Generate advanced test vectors for specific scenarios"""
    generator = AdvancedVectorGenerator()
    
    # Test basic functionality first
    print("Testing basic registration intent generation...")
    try:
        test_vector = generator.generate_registration_intent_vector("alice", 0, 0)
        print(f"✓ Successfully generated test vector for alice")
        print(f"  ETH Address: {test_vector['eth_address']}")
        print(f"  PQ Fingerprint: {test_vector['pq_fingerprint']}")
        print(f"  ETH Nonce: {test_vector['eth_nonce']}")
        print(f"  PQ Nonce: {test_vector['pq_nonce']}")
    except Exception as e:
        print(f"✗ Failed to generate test vector: {e}")
        return
    
    # Define test scenarios
    scenarios = {
        "registration_flow_with_removal": {
            "description": "ETH creates intent → PQ removes → ETH creates new intent → PQ confirms",
            "steps": [
                {"type": "registration_intent", "actor": "alice", "eth_nonce": 0, "pq_nonce": 0, "order": 1},
                {"type": "removal_registration_pq", "actor": "alice", "pq_nonce": 1, "order": 2},
                {"type": "registration_intent", "actor": "alice", "eth_nonce": 1, "pq_nonce": 2, "order": 3},
                {"type": "registration_confirmation", "actor": "alice", "eth_nonce": 2, "pq_nonce": 3, "order": 4}
            ]
        },
        "change_eth_flow_with_cancellation": {
            "description": "Alice changes ETH → PQ cancels → Alice changes to different ETH → confirms",
            "steps": [
                {"type": "registration_intent", "actor": "alice", "eth_nonce": 0, "pq_nonce": 0, "order": 1},
                {"type": "registration_confirmation", "actor": "alice", "eth_nonce": 1, "pq_nonce": 1, "order": 2},
                {"type": "change_eth_intent", "actor": "alice", "new_eth_address": "0x1234567890123456789012345678901234567890", "eth_nonce": 2, "pq_nonce": 2, "order": 3},
                {"type": "removal_change_pq", "actor": "alice", "pq_nonce": 3, "order": 4},
                {"type": "change_eth_intent", "actor": "alice", "new_eth_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "eth_nonce": 3, "pq_nonce": 4, "order": 5},
                {"type": "change_eth_confirmation", "actor": "alice", "new_eth_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "eth_nonce": 4, "pq_nonce": 5, "order": 6}
            ]
        },
        "unregistration_flow_with_revocation": {
            "description": "Alice unregisters → revokes intent → unregisters again → confirms",
            "steps": [
                {"type": "registration_intent", "actor": "alice", "eth_nonce": 0, "pq_nonce": 0, "order": 1},
                {"type": "registration_confirmation", "actor": "alice", "eth_nonce": 1, "pq_nonce": 1, "order": 2},
                {"type": "unregistration_intent", "actor": "alice", "eth_nonce": 2, "pq_nonce": 2, "order": 3},
                {"type": "removal_unregistration_pq", "actor": "alice", "pq_nonce": 3, "order": 4},
                {"type": "unregistration_intent", "actor": "alice", "eth_nonce": 3, "pq_nonce": 4, "order": 5},
                {"type": "unregistration_confirmation", "actor": "alice", "eth_nonce": 4, "pq_nonce": 5, "order": 6}
            ]
        }
    }
    
    # Generate vectors for each scenario
    output_dir = "test/test_vectors/advanced"
    os.makedirs(output_dir, exist_ok=True)
    
    for scenario_name, scenario_config in scenarios.items():
        print(f"\nGenerating vectors for scenario: {scenario_name}")
        try:
            vectors = generator.generate_scenario_vectors(scenario_name, scenario_config)
            
            output_file = os.path.join(output_dir, f"{scenario_name}_vectors.json")
            with open(output_file, 'w') as f:
                json.dump(vectors, f, indent=2)
            
            print(f"Generated {len(vectors['vectors'])} vectors for {scenario_name}")
            print(f"Saved to: {output_file}")
        except Exception as e:
            print(f"✗ Failed to generate scenario {scenario_name}: {e}")
    
    print("\nAdvanced vector generation complete!")

if __name__ == "__main__":
    main() 