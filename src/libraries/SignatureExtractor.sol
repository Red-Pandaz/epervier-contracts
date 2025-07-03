// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/console.sol";

/**
 * @title SignatureExtractor
 * @dev Library for extracting signatures and components from messages
 */
library SignatureExtractor {
    
    // EIP-712 Domain Separator
    string public constant DOMAIN_NAME = "PQRegistry";
    string public constant DOMAIN_VERSION = "1";
    uint256 public constant CHAIN_ID = 11155420; // Optimism Sepolia
    
    // Domain Separator Type Hash
    bytes32 public constant DOMAIN_SEPARATOR_TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    
    // EIP-712 Type Hashes
    bytes32 public constant REGISTRATION_INTENT_TYPE_HASH = keccak256("RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)");
    bytes32 public constant REGISTRATION_CONFIRMATION_TYPE_HASH = keccak256("RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant REMOVE_INTENT_TYPE_HASH = keccak256("RemoveIntent(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH = keccak256("ChangeETHAddressIntent(address newETHAddress,address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH = keccak256("ChangeETHAddressConfirmation(address oldETHAddress,address pqFingerprint,bytes basePQMessage,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,uint256 ethNonce)");
    bytes32 public constant UNREGISTRATION_INTENT_TYPE_HASH = keccak256("UnregistrationIntent(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant UNREGISTRATION_CONFIRMATION_TYPE_HASH = keccak256("UnregistrationConfirmation(address pqFingerprint,bytes basePQMessage,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,uint256 ethNonce)");
    bytes32 public constant REMOVE_CHANGE_INTENT_TYPE_HASH = keccak256("RemoveChangeIntent(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant REMOVE_UNREGISTRATION_INTENT_TYPE_HASH = keccak256("RemoveUnregistrationIntent(uint256 ethNonce)");
    
    /**
     * @dev Extract ETH signature from PQ message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature
     */
    function extractETHSignature(bytes memory message) internal pure returns (bytes memory ethSignature) {
        // Check if message is long enough to contain the pattern + address + nonce + signature
        require(message.length >= 32 + 27 + 20 + 32 + 65, "Message too short for ETH signature");
        
        // Extract the ETH signature from the end of the message (last 65 bytes)
        bytes memory signatureBytes = new bytes(65);
        for (uint j = 0; j < 65; j++) {
            signatureBytes[j] = message[message.length - 65 + j];
        }
        return signatureBytes;
    }

    /**
     * @dev Extract PQ signature salt from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     * Registration format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     * ChangeETHAddress format: DOMAIN_SEPARATOR + "Confirm change ETH Address" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     * Unregistration format: DOMAIN_SEPARATOR + "Confirm unregistration" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractPQSalt(bytes memory message, uint8 messageType) internal pure returns (bytes memory salt) {
        uint256 patternLength;
        if (messageType == 0) {
            // Registration: "Intent to pair Epervier Key" (27 bytes)
            patternLength = 27;
        } else if (messageType == 1) {
            // ChangeETHAddress: "Intent to change ETH Address and bond with Epervier Fingerprint " (64 bytes)
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt
        require(message.length >= 32 + patternLength + 32 + 40, "Message too short for PQ salt");
        
        // Extract the salt (40 bytes after DOMAIN_SEPARATOR + pattern + ethNonce)
        bytes memory saltBytes = new bytes(40);
        for (uint j = 0; j < 40; j++) {
            saltBytes[j] = message[32 + patternLength + 32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + offset
        }
        return saltBytes;
    }

    /**
     * @dev Extract PQ signature cs1 from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractPQCs1(bytes memory message, uint8 messageType) internal pure returns (uint256[] memory cs1) {
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32, "Message too short for PQ cs1");
        
        // Extract cs1 (32 uint256 values after salt)
        cs1 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs1Bytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs1Bytes[j] = message[32 + patternLength + 32 + 40 + i*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + offset
            }
            cs1[i] = abi.decode(cs1Bytes, (uint256));
        }
        return cs1;
    }

    /**
     * @dev Extract PQ signature cs2 from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractPQCs2(bytes memory message, uint8 messageType) internal pure returns (uint256[] memory cs2) {
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32 + 32*32, "Message too short for PQ cs2");
        
        // Extract cs2 (32 uint256 values after cs1)
        cs2 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs2Bytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs2Bytes[j] = message[32 + patternLength + 32 + 40 + 32*32 + i*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + offset
            }
            cs2[i] = abi.decode(cs2Bytes, (uint256));
        }
        return cs2;
    }

    /**
     * @dev Extract PQ signature hint from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractPQHint(bytes memory message, uint8 messageType) internal pure returns (uint256 hint) {
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2 + hint
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32 + 32*32 + 32, "Message too short for PQ hint");
        
        // Extract hint (32 bytes after cs2)
        bytes memory hintBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            hintBytes[j] = message[32 + patternLength + 32 + 40 + 32*32 + 32*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + cs2 + offset
        }
        hint = abi.decode(hintBytes, (uint256));
        
        return hint;
    }

    /**
     * @dev Extract base PQ message from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractBasePQMessage(bytes memory message, uint8 messageType) internal pure returns (bytes memory basePQMessage) {
        if (messageType == 0) {
            // Registration: "Intent to pair Epervier Key" (27 bytes)
            // Format: DOMAIN_SEPARATOR + pattern + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
            uint256 patternLength = 27;
            uint256 baseMessageStart = 32 + patternLength; // DOMAIN_SEPARATOR + pattern
            uint256 baseMessageLength = 111; // BasePQRegistrationIntentMessage length
            
            require(message.length >= baseMessageStart + baseMessageLength, "Message too short for base PQ message");
            
            basePQMessage = new bytes(baseMessageLength);
            for (uint j = 0; j < baseMessageLength; j++) {
                basePQMessage[j] = message[baseMessageStart + j];
            }
            return basePQMessage;
        } else if (messageType == 1) {
            // ChangeETHAddress: "Confirm change ETH Address for Epervier Fingerprint " (52 bytes)
            // Format: DOMAIN_SEPARATOR + pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
            uint256 patternLength = 52;
            uint256 baseMessageStart = 32 + patternLength + 20; // DOMAIN_SEPARATOR + pattern + pqFingerprint
            uint256 baseMessageLength = 173; // BasePQChangeETHAddressConfirmMessage length
            
            require(message.length >= baseMessageStart + baseMessageLength, "Message too short for base PQ message");
            
            basePQMessage = new bytes(baseMessageLength);
            for (uint j = 0; j < baseMessageLength; j++) {
                basePQMessage[j] = message[baseMessageStart + j];
            }
            return basePQMessage;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            // Format: DOMAIN_SEPARATOR + pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
            uint256 patternLength = 49;
            uint256 baseMessageStart = 32 + patternLength + 20; // DOMAIN_SEPARATOR + pattern + pqFingerprint
            uint256 baseMessageLength = 124; // BasePQUnregistrationConfirmMessage length (updated from 123 to 124)
            require(baseMessageStart + baseMessageLength <= message.length, "Message too short for base PQ message");
            basePQMessage = new bytes(baseMessageLength);
            for (uint i = 0; i < baseMessageLength; i++) {
                basePQMessage[i] = message[baseMessageStart + i];
            }
        } else {
            revert("Invalid message type");
        }
    }

    /**
     * @dev Extract fingerprint from PQ message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
     */
    function extractFingerprintFromMessage(bytes memory message) internal pure returns (address fingerprint) {
        // Look for the fingerprint at the end of the message (last 32 bytes)
        require(message.length >= 32, "Message too short for fingerprint");
        
        bytes memory fingerprintBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            fingerprintBytes[i] = message[message.length - 32 + i];
        }
        
        return address(uint160(uint256(bytes32(fingerprintBytes))));
    }
    
    /**
     * @dev Extract PQ nonce from message
     * @param message The message to extract nonce from
     * @param messageType 0 for intent message, 1 for confirmation message
     * Intent format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
     * Confirmation format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
     */
    function extractPQNonce(bytes memory message, uint8 messageType) internal pure returns (uint256 pqNonce) {
        if (messageType == 0) {
            // Intent message format - PQ nonce is at the end
            require(message.length >= 32 + 27 + 20 + 32, "Message too short for PQ nonce from intent message");
            
            // Extract the last 32 bytes as the PQ nonce
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else if (messageType == 1) {
            // Confirmation message format
            require(message.length >= 32 + 40 + 20 + 32, "Message too short for ETH nonce from confirmation message");
            
            // Extract the ETH nonce (last 32 bytes of the message)
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j]; // Last 32 bytes
            }
            return abi.decode(nonceBytes, (uint256));
        } else {
            revert("Invalid message type");
        }
    }

    /**
     * @dev Extract ETH message from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
     */
    function extractETHMessageFromPQMessage(bytes memory message) internal pure returns (bytes memory ethMessage) {
        // Check if message is long enough to contain the pattern + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature
        require(message.length >= 32 + 35 + 20 + 15 + 20 + 32 + 65, "Message too short for ETH message");
        
        // Extract the ETH message (everything after the ETH signature)
        uint256 ethMessageStart = 32 + 35 + 20 + 15 + 20 + 32 + 65; // DOMAIN_SEPARATOR + pattern + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature
        uint256 ethMessageLength = message.length - ethMessageStart;
        
        ethMessage = new bytes(ethMessageLength);
        for (uint j = 0; j < ethMessageLength; j++) {
            ethMessage[j] = message[ethMessageStart + j];
        }
        return ethMessage;
    }

    /**
     * @dev Extract ETH signature from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
     */
    function extractETHSignatureFromPQMessage(bytes memory message) internal pure returns (bytes memory ethSignature) {
        // The signature starts at offset 154 (matching extractETHMessageFromPQMessage and working tests)
        uint256 signatureStart = 32 + 35 + 20 + 15 + 20 + 32; // DOMAIN_SEPARATOR + pattern + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce
        require(message.length >= signatureStart + 65, "Message too short for ETH signature");
        
        bytes memory signatureBytes = new bytes(65);
        for (uint j = 0; j < 65; j++) {
            signatureBytes[j] = message[signatureStart + j];
        }
        return signatureBytes;
    }

    /**
     * @dev Extract fingerprint from ETH message
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + fingerprint + ethNonce
     */
    function extractFingerprintFromETHMessage(bytes memory message) internal pure returns (address fingerprint) {
        require(message.length >= 32 + 40 + 20 + 32, "Message too short for fingerprint from ETH message");
        bytes memory fingerprintBytes = new bytes(20);
        for (uint j = 0; j < 20; j++) {
            fingerprintBytes[j] = message[32 + 40 + j]; // DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + offset
        }
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(fingerprintBytes[j]);
        }
        return address(uint160(addr));
    }

    /**
     * @dev Extract ETH nonce from a message according to schema
     * For intent messages: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ... + ethNonce (last 32 bytes)
     * For confirmation messages: DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + ... + ethNonce (last 32 bytes)
     * @param message The message to extract nonce from
     * @param messageType 0 for intent message, 1 for confirmation message
     */
    function extractEthNonce(bytes memory message, uint8 messageType) internal pure returns (uint256 ethNonce) {
        if (messageType == 0) {
            // Intent message: ETH nonce is the last 32 bytes
            require(message.length >= 32, "Message too short for ETH nonce");
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else if (messageType == 1) {
            // Confirmation message: ETH nonce is the last 32 bytes
            require(message.length >= 32, "Message too short for ETH nonce");
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else {
            revert("Invalid message type");
        }
    }
    
    /**
     * @dev Compute the EIP-712 domain separator
     * @param verifyingContract The address of the verifying contract
     * @return The domain separator as bytes32
     */
    function getDomainSeparator(address verifyingContract) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_SEPARATOR_TYPE_HASH,
                keccak256(bytes(DOMAIN_NAME)),
                keccak256(bytes(DOMAIN_VERSION)),
                CHAIN_ID,
                verifyingContract
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for RegistrationIntent
     */
    function getRegistrationIntentStructHash(
        bytes memory salt,
        uint256[32] memory cs1,
        uint256[32] memory cs2,
        uint256 hint,
        bytes memory basePQMessage,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REGISTRATION_INTENT_TYPE_HASH,
                keccak256(salt),
                keccak256(abi.encodePacked(cs1)),
                keccak256(abi.encodePacked(cs2)),
                hint,
                keccak256(basePQMessage),
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for RegistrationConfirmation
     */
    function getRegistrationConfirmationStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REGISTRATION_CONFIRMATION_TYPE_HASH,
                pqFingerprint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for RemoveIntent
     */
    function getRemoveIntentStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REMOVE_INTENT_TYPE_HASH,
                pqFingerprint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for ChangeETHAddressIntent
     */
    function getChangeETHAddressIntentStructHash(
        address newETHAddress,
        address pqFingerprint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH,
                newETHAddress,
                pqFingerprint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for ChangeETHAddressConfirmation
     */
    function getChangeETHAddressConfirmationStructHash(
        address oldETHAddress,
        address pqFingerprint,
        bytes memory basePQMessage,
        bytes memory salt,
        uint256[32] memory cs1,
        uint256[32] memory cs2,
        uint256 hint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH,
                oldETHAddress,
                pqFingerprint,
                keccak256(basePQMessage),
                keccak256(salt),
                keccak256(abi.encodePacked(cs1)),
                keccak256(abi.encodePacked(cs2)),
                hint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for UnregistrationIntent
     */
    function getUnregistrationIntentStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                UNREGISTRATION_INTENT_TYPE_HASH,
                pqFingerprint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for UnregistrationConfirmation
     */
    function getUnregistrationConfirmationStructHash(
        address pqFingerprint,
        bytes memory basePQMessage,
        bytes memory salt,
        uint256[32] memory cs1,
        uint256[32] memory cs2,
        uint256 hint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                UNREGISTRATION_CONFIRMATION_TYPE_HASH,
                pqFingerprint,
                keccak256(basePQMessage),
                keccak256(salt),
                keccak256(abi.encodePacked(cs1)),
                keccak256(abi.encodePacked(cs2)),
                hint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for RemoveChangeIntent
     */
    function getRemoveChangeIntentStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REMOVE_CHANGE_INTENT_TYPE_HASH,
                pqFingerprint,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 struct hash for RemoveUnregistrationIntent
     */
    function getRemoveUnregistrationIntentStructHash(
        uint256 ethNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REMOVE_UNREGISTRATION_INTENT_TYPE_HASH,
                ethNonce
            )
        );
    }
    
    /**
     * @dev Compute the EIP-712 digest for a struct hash
     * @param domainSeparator The domain separator
     * @param structHash The struct hash
     * @return The EIP-712 digest
     */
    function getEIP712Digest(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

