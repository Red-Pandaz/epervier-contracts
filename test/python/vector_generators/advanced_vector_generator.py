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

# Add the parent directory to the path to import the basic generator
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generate_test_vectors import (
    DOMAIN_SEPARATOR, 
    generate_epervier_signature,
    load_actors_config
)

def generate_eth_signature(message: bytes, private_key: str) -> Dict[str, Any]:
    """Generate ETH signature for a message"""
    from eth_account.messages import encode_defunct
    
    account = Account.from_key(private_key)
    message_hash = encode_defunct(message)
    signed_message = account.sign_message(message_hash)
    
    return {
        "v": signed_message.v,
        "r": signed_message.r,
        "s": signed_message.s,
        "signature": signed_message.signature.hex()
    }

def abi_encode_packed(*args):
    """Concatenate arguments without padding (like Solidity's abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, int):
            # Convert to 32-byte big-endian
            result += arg.to_bytes(32, 'big')
        elif isinstance(arg, list):
            # For arrays, convert each element to 32-byte big-endian
            for item in arg:
                result += item.to_bytes(32, 'big')
        else:
            raise ValueError(f"Unsupported type: {type(arg)}")
    return result

# Message creation functions based on the schema
def create_base_pq_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ registration intent message according to schema"""
    # BasePQRegistrationIntentMessage: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
    pattern = "Intent to pair ETH Address "
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        pattern,
        eth_address,
        pq_nonce
    )

def create_eth_registration_intent_message(base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH registration intent message according to schema"""
    # ETHRegistrationIntentMessage: pattern + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    pattern = "Intent to pair Epervier Key"
    return abi_encode_packed(
        pattern,
        base_pq_message,
        salt,
        cs1,
        cs2,
        hint,
        eth_nonce
    )

def create_base_eth_registration_confirmation_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH registration confirmation message according to schema"""
    # BaseETHRegistrationConfirmationMessage: pattern + pqFingerprint + ethNonce
    pattern = "Confirm bonding to Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        eth_nonce
    )

def create_pq_registration_confirmation_message(eth_address: str, base_eth_message: bytes, v: int, r: bytes, s: bytes, pq_nonce: int) -> bytes:
    """Create PQ registration confirmation message according to schema"""
    # PQRegistrationConfirmationMessage: pattern + ethAddress + baseETHMessage + v + r + s + pqNonce
    pattern = "Confirm binding ETH Address "
    return abi_encode_packed(
        pattern,
        eth_address,
        base_eth_message,
        v,
        r,
        s,
        pq_nonce
    )

def create_base_eth_change_eth_address_intent_message(pq_fingerprint: str, new_eth_address: str, eth_nonce: int) -> bytes:
    """Create base ETH change address intent message according to schema"""
    # BaseETHChangeETHAddressIntentMessage: pattern + pqFingerprint + pattern2 + newEthAddress + ethNonce
    pattern = "Intent to change ETH Address and bond with Epervier Fingerprint "
    pattern2 = " to "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        pattern2,
        new_eth_address,
        eth_nonce
    )

def create_pq_change_eth_address_intent_message(old_eth_address: str, new_eth_address: str, base_eth_message: bytes, v: int, r: bytes, s: bytes, pq_nonce: int) -> bytes:
    """Create PQ change address intent message according to schema"""
    # PQChangeETHAddressIntentMessage: pattern + oldEthAddress + pattern2 + newEthAddress + baseETHMessage + v + r + s + pqNonce
    pattern = "Intent to change bound ETH Address from "
    pattern2 = " to "
    return abi_encode_packed(
        pattern,
        old_eth_address,
        pattern2,
        new_eth_address,
        base_eth_message,
        v,
        r,
        s,
        pq_nonce
    )

def create_base_pq_change_eth_address_confirm_message(old_eth_address: str, new_eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ change address confirmation message according to schema"""
    # BasePQChangeETHAddressConfirmMessage: pattern + oldEthAddress + pattern2 + newEthAddress + pqNonce
    pattern = "Confirm changing bound ETH Address for Epervier Fingerprint from "
    pattern2 = " to "
    return abi_encode_packed(
        pattern,
        old_eth_address,
        pattern2,
        new_eth_address,
        pq_nonce
    )

def create_eth_change_eth_address_confirmation_message(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH change address confirmation message according to schema"""
    # ETHChangeETHAddressConfirmationMessage: pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    pattern = "Confirm change ETH Address for Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        base_pq_message,
        salt,
        cs1,
        cs2,
        hint,
        eth_nonce
    )

def create_base_eth_unregistration_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH unregistration intent message according to schema"""
    # BaseETHUnregistrationIntentMessage: pattern + pqFingerprint + ethNonce
    pattern = "Intent to unregister from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        eth_nonce
    )

def create_pq_unregistration_intent_message(eth_address: str, base_eth_message: bytes, v: int, r: bytes, s: bytes, pq_nonce: int) -> bytes:
    """Create PQ unregistration intent message according to schema"""
    # PQUnregistrationIntentMessage: pattern + currentEthAddress + baseETHMessage + v + r + s + pqNonce
    pattern = "Intent to unregister from Epervier Fingerprint from address "
    return abi_encode_packed(
        pattern,
        eth_address,
        base_eth_message,
        v,
        r,
        s,
        pq_nonce
    )

def create_base_pq_unregistration_confirm_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ unregistration confirmation message according to schema"""
    # BasePQUnregistrationConfirmMessage: pattern + ethAddress + pqNonce
    pattern = "Confirm unregistration from ETH Address "
    return abi_encode_packed(
        pattern,
        eth_address,
        pq_nonce
    )

def create_eth_unregistration_confirmation_message(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH unregistration confirmation message according to schema"""
    # ETHUnregistrationConfirmationMessage: pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    pattern = "Confirm unregistration from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        base_pq_message,
        salt,
        cs1,
        cs2,
        hint,
        eth_nonce
    )

def create_eth_remove_registration_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create ETH remove registration intent message according to schema"""
    # ETHRemoveRegistrationIntentMessage: pattern + pqFingerprint + ethNonce
    pattern = "Remove registration intent from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        eth_nonce
    )

def create_pq_remove_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove registration intent message according to schema"""
    # PQRemoveRegistrationIntentMessage: pattern + ethAddress + pqNonce
    pattern = "Remove registration intent from ETH Address "
    return abi_encode_packed(
        pattern,
        eth_address,
        pq_nonce
    )

def create_eth_remove_change_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create ETH remove change intent message according to schema"""
    # ETHRemoveChangeIntentMessage: pattern + pqFingerprint + ethNonce
    pattern = "Remove change intent from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        eth_nonce
    )

def create_pq_remove_change_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove change intent message according to schema"""
    # PQRemoveChangeIntentMessage: pattern + ethAddress + pqNonce
    pattern = "Remove change intent from ETH Address "
    return abi_encode_packed(
        pattern,
        eth_address,
        pq_nonce
    )

def create_pq_remove_unregistration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove unregistration intent message according to schema"""
    # PQRemoveUnregistrationIntentMessage: pattern + ethAddress + pqNonce
    pattern = "Remove unregistration intent from ETH Address "
    return abi_encode_packed(
        pattern,
        eth_address,
        pq_nonce
    )

class AdvancedVectorGenerator:
    def __init__(self):
        self.w3 = Web3()
        self.account = Account()
        
        # Load actors from the main config
        self.actors_config = load_actors_config()
        
        # Actor configurations with their private keys and addresses
        self.actors = {
            "alice": {
                "eth_private_key": self.actors_config["alice"]["eth_private_key"],
                "eth_address": self.actors_config["alice"]["eth_address"],
                "pq_fingerprint": self.actors_config["alice"]["pq_fingerprint"]
            },
            "bob": {
                "eth_private_key": self.actors_config["bob"]["eth_private_key"],
                "eth_address": self.actors_config["bob"]["eth_address"],
                "pq_fingerprint": self.actors_config["bob"]["pq_fingerprint"]
            },
            "charlie": {
                "eth_private_key": self.actors_config["charlie"]["eth_private_key"],
                "eth_address": self.actors_config["charlie"]["eth_address"],
                "pq_fingerprint": self.actors_config["charlie"]["pq_fingerprint"]
            }
        }
    
    def generate_registration_intent_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base PQ message
        base_pq_message = create_base_pq_registration_intent_message(
            actor_data["eth_address"], 
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Create ETH message
        eth_message = create_eth_registration_intent_message(
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
    
    def generate_change_eth_address_intent_vector(self, actor: str, new_eth_address: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a change ETH address intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base ETH change intent message
        base_eth_message = create_base_eth_change_eth_address_intent_message(
            actor_data["pq_fingerprint"],
            new_eth_address,
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = generate_eth_signature(base_eth_message, actor_data["eth_private_key"])
        
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
            "old_eth_address": actor_data["eth_address"],
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
        
        # Generate ETH signature
        eth_signature = generate_eth_signature(eth_message, actor_data["eth_private_key"])
        
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
        print(f"Generating vectors for scenario: {scenario_name}")
        vectors = generator.generate_scenario_vectors(scenario_name, scenario_config)
        
        output_file = os.path.join(output_dir, f"{scenario_name}_vectors.json")
        with open(output_file, 'w') as f:
            json.dump(vectors, f, indent=2)
        
        print(f"Generated {len(vectors['vectors'])} vectors for {scenario_name}")
        print(f"Saved to: {output_file}")
    
    print("\nAdvanced vector generation complete!")

if __name__ == "__main__":
    main() 