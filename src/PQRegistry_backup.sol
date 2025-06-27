// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./libraries/MessageParser.sol";
import "./libraries/MessageValidation.sol";
import "./libraries/SignatureExtractor.sol";
import "./libraries/AddressUtils.sol";

// TODO: Add a function that allows ETH Address to remove ChangeEThAddressIntent
/**
 * @title PQRegistry
 * @dev Registry for Epervier public keys with nonce tracking to prevent replay attacks
 * Requires both Epervier signature and ECDSA signature from the same address
 */
contract PQRegistry {
    ZKNOX_epervier public immutable epervierVerifier;
    
    // Domain separator for replay protection
    bytes32 public constant DOMAIN_SEPARATOR = keccak256("PQRegistry");
    
    // Mapping from Epervier public key address to Ethereum address
    mapping(address => address) public epervierKeyToAddress;
    
    // Mapping from Ethereum address to Epervier public key address
    mapping(address => address) public addressToEpervierKey;
    
    // Nonces for ETH Addresses (per domain)
    mapping(address => uint256) public ethNonces;
    
    // Nonces for PQ keys (existing)
    mapping(address => uint256) public pqKeyNonces;
    
    // Pending intents for two-step registration - ETH Address controls their intent
    struct Intent {
        address pqFingerprint;
        bytes intentMessage;
        uint256 timestamp;
    }
    mapping(address => Intent) public pendingIntents;
    
    // Bidirectional mapping: PQ fingerprint to ETH Address with pending intent
    mapping(address => address) public pqFingerprintToPendingIntentAddress;
    
    // Pending change ETH Address intents - PQ key controls their intent
    struct ChangeETHAddressIntent {
        address newETHAddress;
        bytes pqMessage;
        uint256 timestamp;
        uint256 pqNonce;
    }
    mapping(address => ChangeETHAddressIntent) public changeETHAddressIntents;
    
    // Special constant for disabled PQ security
    address constant public DISABLED_PQ_KEY = address(1);
    
    struct UnregistrationIntent {
        uint256[2] publicKey;
        address publicKeyAddress;
        bytes pqMessage;
        uint256 timestamp;
    }
    
    mapping(address => UnregistrationIntent) public unregistrationIntents;
    
    event EpervierKeyDeleted(address indexed owner, address indexed publicKeyAddress);
    event PQSecurityDisabled(address indexed owner);
    event PQSecurityEnabled(address indexed owner, address indexed publicKeyAddress);
    event RegistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationIntentRemoved(address indexed ethAddress);
    event IntentRemoved(address indexed owner);
    event ChangeETHAddressIntentSubmitted(address indexed pqFingerprint, address indexed newETHAddress, uint256 pqNonce);
    event ChangeETHAddressConfirmed(address indexed pqFingerprint, address indexed oldETHAddress, address indexed newETHAddress);
    event ChangeETHAddressIntentRemoved(address indexed pqFingerprint);
    event UnregistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint);
    event UnregistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event UnregistrationIntentRemoved(address indexed ethAddress);
    event DebugParsedIntentAddress(address parsedAddress);
    event DebugParseStep(string step, uint256 value);
    event DebugEthMessageHex(bytes ethMessage);
    event DebugAddress(string label, address addr);
    
    constructor(address _epervierVerifier) {
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        epervierVerifier = ZKNOX_epervier(_epervierVerifier);
    }
    
    // ============ HELPER FUNCTIONS ============
    
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
    function extractETHSignatureFromPQMessage(bytes memory message) internal returns (bytes memory ethSignature) {
        // The signature starts at offset 154 (matching extractETHMessageFromPQMessage and working tests)
        uint256 signatureStart = 32 + 35 + 20 + 15 + 20 + 32; // DOMAIN_SEPARATOR + pattern + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce
        require(message.length >= signatureStart + 65, "Message too short for ETH signature");
        
        // Debug: Print the bytes around the expected signature position
        emit DebugParseStep("signature_start_offset", signatureStart);
        emit DebugParseStep("message_length", message.length);
        
        // Print the first few bytes of the expected signature position
        for (uint i = 0; i < 10 && i < 65; i++) {
            emit DebugParseStep("expected_signature_byte", uint8(message[signatureStart + i]));
        }
        
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
     * @dev Parse current ETH Address from change address message
     * Expected format: DOMAIN_SEPARATOR + "Change bound ETH Address from " + currentAddress + " to " + newAddress + pqNonce
     */
    function parseCurrentETHAddress(bytes memory message) internal pure returns (address currentAddress) {
        // Look for the pattern "Change bound ETH Address from " followed by an address
        bytes memory pattern = "Change bound ETH Address from ";
        
        // Find the pattern in the message
        uint patternIndex = findPattern(message, pattern);
        if (patternIndex == type(uint).max) {
            return address(0);
        }
        
        // Extract the current address (20 bytes after the pattern)
        uint addressStart = patternIndex + pattern.length;
        if (addressStart + 20 > message.length) {
            return address(0);
        }
        
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[addressStart + i];
        }
        
        return address(uint160(uint256(bytes32(addressBytes))));
    }

    /**
     * @dev Parse new ETH Address from change address message
     * Expected format: DOMAIN_SEPARATOR + "Change bound ETH Address from " + currentAddress + " to " + newAddress + pqNonce
     */
    function parseNewETHAddress(bytes memory message) internal pure returns (address newAddress) {
        // Look for the pattern " to " followed by an address
        bytes memory pattern = " to ";
        
        // Find the pattern in the message
        uint patternIndex = findPattern(message, pattern);
        if (patternIndex == type(uint).max) {
            return address(0);
        }
        
        // Extract the new address (20 bytes after the pattern)
        uint addressStart = patternIndex + pattern.length;
        if (addressStart + 20 > message.length) {
            return address(0);
        }
        
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[addressStart + i];
        }
        
        return address(uint160(uint256(bytes32(addressBytes))));
    }

    /**
     * @dev Find a pattern in a byte array
     * @param data The data to search in
     * @param pattern The pattern to find
     * @param skipDomainSeparator Whether to skip the first 32 bytes (DOMAIN_SEPARATOR)
     */
    function findPattern(bytes memory data, bytes memory pattern, bool skipDomainSeparator) internal pure returns (uint index) {
        if (pattern.length > data.length) {
            return type(uint).max;
        }
        
        uint startIndex = skipDomainSeparator ? 32 : 0;
        if (startIndex >= data.length) {
            return type(uint).max;
        }
        
        for (uint i = startIndex; i <= data.length - pattern.length; i++) {
            bool found = true;
            for (uint j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        
        return type(uint).max;
    }

    /**
     * @dev Find a pattern in a byte array (backward compatibility)
     */
    function findPattern(bytes memory data, bytes memory pattern) internal pure returns (uint index) {
        return findPattern(data, pattern, false);
    }

    /**
     * @dev Validate that ETH message contains confirmation text for changing ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address" + ethNonce + pqMessage
     */
    function validateETHConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm change ETH Address";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for changing ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing ETH Address from " + currentAddress + " to " + newAddress + pqNonce
     */
    function validatePQConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm changing ETH Address from ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for change ETH Address intent
     * Expected format: DOMAIN_SEPARATOR + "Remove change ETH Address intent" + currentAddress + pqNonce
     */
    function validatePQRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove change ETH Address intent";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + ethNonce + pqMessage
     */
    function validateETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
     */
    function validatePQUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from ETH Address ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for unregistration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce
     */
    function validatePQUnregistrationRemovalMessage(bytes memory message) internal returns (bool) {
        bytes memory pattern = "Remove unregistration intent from ETH Address ";
        
        // Debug: Log the pattern we're looking for
        emit DebugParseStep("pattern_length", pattern.length);
        emit DebugParseStep("message_length", message.length);
        
        // Debug: Log the first 50 bytes of the pattern
        for (uint i = 0; i < 50 && i < pattern.length; i++) {
            emit DebugParseStep("pattern_byte", uint8(pattern[i]));
        }
        
        // Debug: Log the first 50 bytes of the message
        for (uint i = 0; i < 50 && i < message.length; i++) {
            emit DebugParseStep("message_byte", uint8(message[i]));
        }
        
        // Debug: Log the bytes starting from position 32 (after DOMAIN_SEPARATOR)
        emit DebugParseStep("message_start_index", 32);
        for (uint i = 32; i < 82 && i < message.length; i++) {
            emit DebugParseStep("message_after_domain", uint8(message[i]));
        }
        
        uint256 patternIndex = findPattern(message, pattern, true); // Skip DOMAIN_SEPARATOR
        emit DebugParseStep("pattern_found_at", patternIndex);
        
        return patternIndex != type(uint).max;
    }

    function addressToBytes32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function bytes32ToAddress(bytes32 b) internal pure returns (address) {
        return address(uint160(uint256(b)));
    }

    // ============ MAIN FUNCTIONS ============

    function submitRegistrationIntent(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // FIRST: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        emit DebugParseStep("eth_message_length", ethMessage.length);
        emit DebugParseStep("eth_message_hash", uint256(ethMessageHash));
        emit DebugParseStep("eth_signed_message_hash", uint256(ethSignedMessageHash));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        emit DebugParseStep("eth_signature_recovered", uint256(uint160(recoveredETHAddress)));
        require(recoveredETHAddress != address(0), "ERR1: Invalid ETH signature");
    
        
        // SECOND: Parse the ETH registration intent message using our standardized schema
        (
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = MessageParser.parseETHRegistrationIntentMessage(ethMessage);
        
        // Debug logging for extracted components
        emit DebugParseStep("extracted_hint", hint);
        emit DebugParseStep("salt_length", salt.length);
        emit DebugParseStep("cs1_length", cs1.length);
        emit DebugParseStep("cs2_length", cs2.length);
        emit DebugParseStep("base_pq_message_length", basePQMessage.length);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        require(pendingIntents[recoveredETHAddress].timestamp == 0, "ERR7: ETH Address has pending intent");
        require(addressToEpervierKey[recoveredETHAddress] == address(0), "ERR8: ETH Address is already registered");
        require(epervierKeyToAddress[recoveredFingerprint] == address(0), "ERR9: PQ fingerprint is already registered");
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated during confirmation by comparing fingerprints
        
        // FOURTH: Parse the base PQ message using our standardized schema
        (address intentAddress, uint256 pqNonce) = MessageParser.parseBasePQRegistrationIntentMessage(basePQMessage);
        emit DebugParseStep("recovered_eth_address", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address", uint256(uint160(intentAddress)));
        emit DebugParseStep("current_eth_nonce", ethNonces[intentAddress]);

        
        // Debug: Log the address comparison
        emit DebugParseStep("recovered_eth_address_uint", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address_uint", uint256(uint160(intentAddress)));
        emit DebugParseStep("addresses_equal", uint256(uint160(recoveredETHAddress == intentAddress ? 1 : 0)));
        require(intentAddress == recoveredETHAddress, "ERR3: ETH signature must be from intent address");
        
        // FIFTH: Verify ETH nonce
        emit DebugParseStep("confirm_eth_nonce_extracted", ethNonce);
        emit DebugParseStep("confirm_eth_nonce_expected", ethNonces[intentAddress]);
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "ERR4: Invalid PQ nonce in submitRegistrationIntent");
        require(ethNonces[intentAddress] == ethNonce, "ERR6: Invalid ETH nonce in submitRegistrationIntent");
        
        // Check if Epervier key is already registered
        require(addressToEpervierKey[intentAddress] == address(0), "ERR5: Epervier key already registered");
        
        // SIXTH: Conflict prevention: Check for other pending intents
        // Check for pending change intents
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        
        // Check for pending unregistration intents
        require(unregistrationIntents[intentAddress].timestamp == 0, "ETH Address has pending unregistration intent");
        
        // Store the intent with the recovered fingerprint address directly
        pendingIntents[intentAddress] = Intent({
            pqFingerprint: recoveredFingerprint,  // Use recovered address directly
            intentMessage: basePQMessage,
            timestamp: block.timestamp
        });
        
        // Store the bidirectional mapping: PQ fingerprint to ETH Address
        pqFingerprintToPendingIntentAddress[recoveredFingerprint] = intentAddress;
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        // Increment PQ nonce to prevent replay attacks
        pqKeyNonces[recoveredFingerprint]++;  // Use recovered address directly
        
        emit RegistrationIntentSubmitted(intentAddress, recoveredFingerprint);
    }
    
    /**
     * @dev Confirm registration with nested signatures
     * @param pqMessage The PQ message signed by Epervier (contains ETH nonce and signature)
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     */
    function confirmRegistration(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        emit DebugParseStep("confirmRegistration_started", 0);
        emit DebugParseStep("pqMessage_length", pqMessage.length);
        
        // FIRST: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        emit DebugParseStep("epervier_recover_successful", uint256(uint160(recoveredFingerprint)));
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Parse the PQ registration confirmation message using our standardized schema
        (
            address ethAddress,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s,
            uint256 pqNonce
        ) = MessageParser.parsePQRegistrationConfirmationMessage(pqMessage);
        
        // Add debug logging to see the PQ message structure
        emit DebugParseStep("pq_message_total_length", pqMessage.length);
        emit DebugParseStep("extracted_eth_message_length", baseETHMessage.length);
        emit DebugParseStep("extracted_eth_signature_length", 65); // v + r + s = 1 + 32 + 32 = 65
        
        // Debug: Print the length and first 64 bytes of the ETH message
        emit DebugParseStep("eth_message_length", baseETHMessage.length);
        // Debug: Print the first 64 bytes of the ETH message
        for (uint i = 0; i < 64 && i < baseETHMessage.length; i++) {
            emit DebugParseStep("eth_message_byte", uint8(baseETHMessage[i]));
        }
        
        // THIRD: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(baseETHMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(baseETHMessage.length), baseETHMessage));
        emit DebugParseStep("confirm_eth_message_length", baseETHMessage.length);
        emit DebugParseStep("confirm_eth_message_hash", uint256(ethMessageHash));
        emit DebugParseStep("confirm_eth_signed_message_hash", uint256(ethSignedMessageHash));
        emit DebugParseStep("confirm_eth_signature_v", v);
        emit DebugParseStep("confirm_eth_signature_r", uint256(r));
        emit DebugParseStep("confirm_eth_signature_s", uint256(s));
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        emit DebugParseStep("confirm_eth_recovered_address", uint256(uint160(recoveredETHAddress)));
        require(recoveredETHAddress != address(0), "Invalid ETH signature");

        // FOURTH: Parse the base ETH confirmation message using our standardized schema
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseBaseETHRegistrationConfirmationMessage(baseETHMessage);
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. ETH Address from PQ message must match recovered ETH Address from ETH signature
        require(ethAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        
        // 2. PQ fingerprint from ETH message must match recovered PQ fingerprint from PQ signature
        require(pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // 3. Check that there's a pending intent for this ETH Address
        Intent storage intent = pendingIntents[ethAddress];
        require(intent.timestamp != 0, "No pending intent found for ETH Address");
        
        // 4. ETH Address from PQ message must match the stored intent ETH Address
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] == ethAddress, "ETH Address mismatch: PQ message vs stored intent");
        
        // 5. PQ fingerprint from ETH message must match the stored intent PQ fingerprint
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        
        // 6. Recovered PQ fingerprint must match the stored intent PQ fingerprint
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        
        emit DebugParseStep("confirm_intent_address", uint256(uint160(ethAddress)));
        emit DebugParseStep("recovered_eth_address_uint", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address_uint", uint256(uint160(ethAddress)));
        emit DebugParseStep("addresses_equal", uint256(uint160(recoveredETHAddress == ethAddress ? 1 : 0)));

        // SIXTH: Verify nonces
        emit DebugParseStep("confirm_eth_nonce_extracted", ethNonce);
        emit DebugParseStep("confirm_eth_nonce_expected", ethNonces[ethAddress]);
        emit DebugParseStep("confirm_pq_nonce_extracted", pqNonce);
        emit DebugParseStep("confirm_pq_nonce_expected", pqKeyNonces[recoveredFingerprint]);
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "ERR4: Invalid PQ nonce in confirmRegistration");
        require(ethNonces[ethAddress] == ethNonce, "ERR6: Invalid ETH nonce in confirmRegistration");

        // SEVENTH: Complete the registration
        epervierKeyToAddress[recoveredFingerprint] = ethAddress;
        addressToEpervierKey[ethAddress] = recoveredFingerprint;
        
        // Clear the pending intent and bidirectional mapping
        delete pendingIntents[ethAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // Increment PQ nonce
        pqKeyNonces[recoveredFingerprint]++;
        
        // Increment ETH nonce
        ethNonces[ethAddress]++;

        emit RegistrationConfirmed(ethAddress, recoveredFingerprint);
    }
    
    /**
     * @dev Extract ETH nonce from remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function extractEthNonceFromRemoveMessage(bytes memory message) internal pure returns (uint256 ethNonce) {
        require(message.length >= 32 + 26 + 32, "Message too short for ETH nonce from remove message");
        
        // Extract the ETH nonce (32 bytes after DOMAIN_SEPARATOR + "Remove intent from address")
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[32 + 26 + j]; // DOMAIN_SEPARATOR + "Remove intent from address" + offset
        }
        return abi.decode(nonceBytes, (uint256));
    }

    /**
     * @dev Extract fingerprint from remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function extractFingerprintFromRemoveMessage(bytes memory message) internal pure returns (address fingerprint) {
        require(message.length >= 32 + 26 + 32 + 20, "Message too short for fingerprint from remove message");
        
        // Extract the fingerprint (last 20 bytes of the message for address)
        bytes memory fingerprintBytes = new bytes(20);
        for (uint j = 0; j < 20; j++) {
            fingerprintBytes[j] = message[message.length - 20 + j]; // Last 20 bytes
        }
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(fingerprintBytes[j]);
        }
        return address(uint160(addr));
    }

    /**
     * @dev Remove a pending registration intent (ETH controlled)
     * @param ethMessage The ETH message containing the remove intent request
     * @param v The ETH signature v component
     * @param r The ETH signature r component  
     * @param s The ETH signature s component
     */
    function removeIntent(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // FIRST: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // SECOND: Parse the ETH remove intent message using our standardized schema
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseETHRemoveRegistrationIntentMessage(ethMessage);
        
        // THIRD: Comprehensive cross-reference validation
        // 1. Check if there's a pending intent for the recovered ETH Address
        Intent storage intent = pendingIntents[recoveredETHAddress];
        require(intent.timestamp != 0, "No pending intent found for recovered ETH Address");
        
        // 2. Verify the referenced PQ fingerprint matches the stored intent
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        
        // 3. Verify the bidirectional mapping is consistent
        require(pqFingerprintToPendingIntentAddress[pqFingerprint] == recoveredETHAddress, "Bidirectional mapping mismatch");
        
        // FOURTH: Verify ETH nonce
        require(ethNonces[recoveredETHAddress] == ethNonce, "ERR7: Invalid ETH nonce in removeIntent");
        
        // Store the PQ fingerprint before clearing the intent
        address pqFingerprintToClear = intent.pqFingerprint;
        
        // Clear the intent
        delete pendingIntents[recoveredETHAddress];
        delete pqFingerprintToPendingIntentAddress[pqFingerprintToClear];
        
        // Increment ETH nonce
        ethNonces[recoveredETHAddress]++;
        
        emit RegistrationIntentRemoved(recoveredETHAddress);
    }
    
    /**
     * @dev Remove a pending change ETH Address intent (ETH controlled)
     * @param ethMessage The ETH message containing the remove change intent request
     * @param v The ETH signature v component
     * @param r The ETH signature r component  
     * @param s The ETH signature s component
     */
    function removeChangeETHAddressIntentByETH(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // FIRST: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // SECOND: Parse the ETH remove change intent message using our standardized schema
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseETHRemoveChangeIntentMessage(ethMessage);
        
        // THIRD: Comprehensive cross-reference validation
        // 1. Check if there's a pending change intent for this PQ fingerprint
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[pqFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        
        // 2. Verify the ETH Address from the message matches the current registration
        require(addressToEpervierKey[recoveredETHAddress] == pqFingerprint, "ETH Address not registered to PQ fingerprint");
        
        // 3. Verify the PQ fingerprint is currently registered to the ETH Address
        require(epervierKeyToAddress[pqFingerprint] == recoveredETHAddress, "PQ fingerprint not registered to ETH Address");
        
        // FOURTH: Verify ETH nonce
        require(ethNonces[recoveredETHAddress] == ethNonce, "ERR12: Invalid ETH nonce in removeChangeETHAddressIntentByETH");
        
        // Clear the intent
        delete changeETHAddressIntents[pqFingerprint];
        
        // Increment ETH nonce
        ethNonces[recoveredETHAddress]++;
        
        emit ChangeETHAddressIntentRemoved(pqFingerprint);
    }
    
    /**
     * @dev Parse intent/confirmation message to extract address
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
     */
    function parseIntentAddress(bytes memory message) public returns (address intentAddress) {
        emit DebugParseStep("message_length", message.length);
        
        // Check if message is long enough to contain the pattern + address + nonce
        if (message.length < 32 + 27 + 20 + 32) { // DOMAIN_SEPARATOR + pattern + address + nonce
            emit DebugParseStep("message_too_short", 0);
            emit DebugParsedIntentAddress(address(0));
            return address(0);
        }
        
        // Create the pattern to search for: "Intent to pair ETH Address "
        bytes memory keyPattern = new bytes(27);
        keyPattern[0] = 0x49; // 'I'
        keyPattern[1] = 0x6e; // 'n'
        keyPattern[2] = 0x74; // 't'
        keyPattern[3] = 0x65; // 'e'
        keyPattern[4] = 0x6e; // 'n'
        keyPattern[5] = 0x74; // 't'
        keyPattern[6] = 0x20; // ' '
        keyPattern[7] = 0x74; // 't'
        keyPattern[8] = 0x6f; // 'o'
        keyPattern[9] = 0x20; // ' '
        keyPattern[10] = 0x70; // 'p'
        keyPattern[11] = 0x61; // 'a'
        keyPattern[12] = 0x69; // 'i'
        keyPattern[13] = 0x72; // 'r'
        keyPattern[14] = 0x20; // ' '
        keyPattern[15] = 0x45; // 'E'
        keyPattern[16] = 0x54; // 'T'
        keyPattern[17] = 0x48; // 'H'
        keyPattern[18] = 0x20; // ' '
        keyPattern[19] = 0x41; // 'A'
        keyPattern[20] = 0x64; // 'd'
        keyPattern[21] = 0x64; // 'd'
        keyPattern[22] = 0x72; // 'r'
        keyPattern[23] = 0x65; // 'e'
        keyPattern[24] = 0x73; // 's'
        keyPattern[25] = 0x73; // 's'
        keyPattern[26] = 0x20; // ' '
        
        // Start searching after the DOMAIN_SEPARATOR (offset 32)
        uint startOffset = 32;
        uint maxSearchIndex = message.length - 47; // 27 bytes pattern + 20 bytes address + 32 bytes nonce
        
        for (uint i = startOffset; i <= maxSearchIndex; i++) {
            emit DebugParseStep("searching_at", i);
            bool found = true;
            for (uint j = 0; j < 27; j++) {
                if (message[i + j] != keyPattern[j]) {
                    found = false;
                    emit DebugParseStep("mismatch_at", j);
                    emit DebugParseStep("expected", uint256(uint8(keyPattern[j])));
                    emit DebugParseStep("got", uint256(uint8(message[i + j])));
                    break;
                }
            }
            
            if (found) {
                emit DebugParseStep("found_intent_at", i);
                
                // Extract the next 20 bytes as the address
                bytes memory addressBytes = new bytes(20);
                for (uint j = 0; j < 20; j++) {
                    addressBytes[j] = message[i + 27 + j]; // Skip the "Intent to pair ETH Address " pattern
                }
                
                // Convert bytes to address - fix the conversion
                uint256 addr = 0;
                for (uint j = 0; j < 20; j++) {
                    addr = (addr << 8) | uint8(addressBytes[j]);
                }
                address parsed = address(uint160(addr));
                emit DebugParseStep("final_addr", uint256(uint160(parsed)));
                emit DebugParsedIntentAddress(parsed);
                return parsed;
            }
        }
        
        emit DebugParseStep("no_intent_found", 0);
        emit DebugParsedIntentAddress(address(0));
        return address(0);
    }

    function debugParseIntentAddress(bytes calldata message) external {
        emit DebugParseStep("message_length", message.length);
        
        // If message is too short, return zero address
        if (message.length < 42) { // "0x" + 40 hex chars
            emit DebugParseStep("message_too_short", 0);
            emit DebugParsedIntentAddress(address(0));
            return;
        }
        
        // Look for the address pattern in the message
        // The address should be 42 bytes (20 bytes address + "0x" prefix)
        // We'll search for "0x" followed by 40 hex characters
        
        for (uint i = 0; i <= message.length - 42; i++) {
            // Check if we found "0x"
            if (message[i] == 0x30 && message[i + 1] == 0x78) { // "0x" in hex
                emit DebugParseStep("found_0x_at", i);
                
                // Extract the next 40 bytes as the address
                bytes memory addressBytes = new bytes(42);
                for (uint j = 0; j < 42; j++) {
                    addressBytes[j] = message[i + j];
                }
                
                // Convert hex string to address
                // This is a simplified conversion - in production you'd want more robust hex parsing
                uint256 addr = 0;
                for (uint j = 2; j < 42; j++) { // Skip "0x"
                    uint256 digit = 0;
                    uint8 byteVal = uint8(addressBytes[j]);
                    if (byteVal >= 0x30 && byteVal <= 0x39) { // 0-9
                        digit = byteVal - 0x30;
                    } else if (byteVal >= 0x61 && byteVal <= 0x66) { // a-f
                        digit = byteVal - 0x61 + 10;
                    } else if (byteVal >= 0x41 && byteVal <= 0x46) { // A-F
                        digit = byteVal - 0x41 + 10;
                    } else {
                        // Skip invalid characters instead of continuing
                        continue;
                    }
                    addr = addr * 16 + digit;
                }
                
                emit DebugParseStep("final_addr", addr);
                address parsed = address(uint160(addr));
                emit DebugParsedIntentAddress(parsed);
                return;
            }
        }
        
        emit DebugParseStep("no_0x_found", 0);
        emit DebugParsedIntentAddress(address(0));
    }

    function submitChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        // FIRST: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Parse the PQ change address intent message using our standardized schema
        (address oldEthAddress, address newEthAddress, uint256 pqNonce, bytes memory baseETHMessage, uint8 v, bytes32 r, bytes32 s) = MessageParser.parsePQChangeETHAddressIntentMessage(pqMessage);
        
        // Debug: Print the extracted values
        emit DebugParseStep("extracted_old_eth_address", uint256(uint160(oldEthAddress)));
        emit DebugParseStep("extracted_new_eth_address", uint256(uint160(newEthAddress)));
        emit DebugParseStep("extracted_pq_nonce", pqNonce);
        
        // THIRD: Verify the ETH signature using the extracted base ETH message
        bytes32 ethMessageHash = keccak256(baseETHMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(baseETHMessage.length), baseETHMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // FOURTH: Parse the base ETH message to extract the pqFingerprint, new ETH Address, and ETH nonce
        (address ethMessagePqFingerprint, address ethMessageNewEthAddress, uint256 ethNonce) = MessageParser.parseBaseETHChangeETHAddressIntentMessage(baseETHMessage);
        
        // Debug: Print the ETH nonce from the base ETH message
        emit DebugParseStep("extracted_eth_nonce_from_base", ethNonce);
        emit DebugParseStep("expected_eth_nonce", ethNonces[newEthAddress]);
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. PQ signature address (recoveredFingerprint) must be currently registered
        address currentETHAddress = epervierKeyToAddress[recoveredFingerprint];
        require(currentETHAddress != address(0), "PQ fingerprint not registered");
        
        // 2. ETH message must be signed by the new ETH Address (not the current one)
        require(newEthAddress == recoveredETHAddress, "ETH signature must be from new ETH Address");
        
        // 3. Old ETH Address from PQ message must match the current registration
        require(oldEthAddress == currentETHAddress, "Old ETH Address mismatch: PQ message vs current registration");
        
        // 4. ETH message must reference the PQ address (recoveredFingerprint)
        require(ethMessagePqFingerprint == recoveredFingerprint, "ETH message PQ fingerprint mismatch");
        require(ethMessageNewEthAddress == newEthAddress, "ETH message new ETH Address mismatch");
        
        // 5. PQ fingerprint must be currently registered to the old ETH Address
        require(addressToEpervierKey[currentETHAddress] == recoveredFingerprint, "PQ key not registered to current address");
        
        // 6. Verify the new ETH Address is different from the current one
        require(newEthAddress != currentETHAddress, "New ETH Address must be different from current address");
        
        // 7. Check if the new ETH Address already has a registered PQ key
        require(addressToEpervierKey[newEthAddress] == address(0), "New ETH Address already has registered PQ key");
        
        // 8. Conflict prevention: Check for other pending intents
        // Check for pending registration intents
        require(pendingIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(pendingIntents[newEthAddress].timestamp == 0, "New ETH Address has pending registration intent");
        
        // Check for pending unregistration intents
        require(unregistrationIntents[currentETHAddress].timestamp == 0, "Current ETH Address has pending unregistration intent");
        require(unregistrationIntents[newEthAddress].timestamp == 0, "New ETH Address has pending unregistration intent");
        
        // Check for other pending change intents
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        
        // SIXTH: Verify nonces
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // Debug output for ETH nonce
        console.log("Expected ETH nonce:", ethNonce);
        console.log("Actual ETH nonce for new address:", ethNonces[newEthAddress]);
        console.log("New ETH Address:", newEthAddress);
        
        require(ethNonces[newEthAddress] == ethNonce, "Invalid ETH nonce");
        
        // Store the change intent
        changeETHAddressIntents[recoveredFingerprint] = ChangeETHAddressIntent({
            newETHAddress: newEthAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp,
            pqNonce: pqKeyNonces[recoveredFingerprint] // Use current PQ nonce
        });
        
        // Increment PQ nonce
        pqKeyNonces[recoveredFingerprint]++;
        // Increment ETH nonce for the new address
        ethNonces[newEthAddress]++;

        emit ChangeETHAddressIntentSubmitted(recoveredFingerprint, newEthAddress, ethNonce);
    }
    
    function confirmChangeETHAddress(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // FIRST: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // SECOND: Parse the ETH change address confirmation message using our standardized schema
        (
            address pqFingerprint,
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = MessageParser.parseETHChangeETHAddressConfirmationMessage(ethMessage);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // FOURTH: Parse the base PQ change address confirmation message using our standardized schema
        (address oldEthAddress, address newEthAddress, uint256 pqNonce) = MessageParser.parseBasePQChangeETHAddressConfirmMessage(basePQMessage);
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. New ETH Address from PQ message must match recovered ETH Address from ETH signature
        require(newEthAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        
        // 2. Check that there's a pending change intent for this PQ fingerprint
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        
        // 3. New ETH Address from PQ message must match the stored intent new ETH Address
        require(intent.newETHAddress == newEthAddress, "ETH Address mismatch: PQ message vs stored intent");
        
        // 4. Old ETH Address from PQ message must match the current registration
        require(addressToEpervierKey[oldEthAddress] == recoveredFingerprint, "Old ETH Address mismatch: PQ message vs current registration");
        
        // 5. PQ fingerprint must be currently registered to the old ETH Address
        require(epervierKeyToAddress[recoveredFingerprint] == oldEthAddress, "PQ fingerprint not registered to old ETH Address");

        // SIXTH: Verify nonces
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[newEthAddress] == ethNonce, "Invalid ETH nonce");
        
        // SEVENTH: Complete the change
        epervierKeyToAddress[recoveredFingerprint] = newEthAddress;
        addressToEpervierKey[oldEthAddress] = address(0); // Clear old mapping
        addressToEpervierKey[newEthAddress] = recoveredFingerprint; // Set new mapping
        
        // Clear the intent
        delete changeETHAddressIntents[recoveredFingerprint];
        
        // Increment nonces
        pqKeyNonces[recoveredFingerprint]++;
        ethNonces[newEthAddress]++;
        
        emit ChangeETHAddressConfirmed(recoveredFingerprint, oldEthAddress, newEthAddress);
    }
    
    /**
     * @dev Submit unregistration intent with nested signatures
     * @param pqMessage The PQ message signed by Epervier (contains ETH Address, nonce, and signature)
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param publicKey The Epervier public key to be unregistered
     */
    function submitUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey
    ) external {
        // FIRST: Verify the PQ signature and recover the ETH Address
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Parse the PQ unregistration intent message to extract ETH signature components
        (
            address parsedEthAddress,
            uint256 parsedPQNonce,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = MessageParser.parsePQUnregistrationIntentMessage(pqMessage);
        
        address intentAddress = parsedEthAddress;
        require(intentAddress != address(0), "Invalid intent address");
        emit DebugAddress("intentAddress", intentAddress);
        
        require(intentAddress == epervierKeyToAddress[recoveredAddress], "ETH Address mismatch: PQ message vs stored registration");
        require(pendingIntents[recoveredAddress].timestamp == 0, "Epervier Fingerprint has pending registration intent");
        
        // THIRD: Extract ETH nonce from the baseETHMessage (which contains the ETH nonce at the end)
        uint256 ethNonce = MessageParser.extractEthNonce(baseETHMessage, 0);
        
        // FOURTH: Verify ETH nonce
        emit DebugParseStep("extracted_eth_nonce", ethNonce);
        emit DebugParseStep("expected_eth_nonce", ethNonces[intentAddress]);
        require(ethNonces[intentAddress] == ethNonce, "ERR10: Invalid ETH nonce in submitUnregistrationIntent");
        
        // SIXTH: Verify PQ nonce from message
        require(pqKeyNonces[recoveredAddress] == parsedPQNonce, "ERR12: Invalid PQ nonce in submitUnregistrationIntent");
        
        // SEVENTH: Check if this address has a registered key
        address publicKeyAddress = recoveredAddress;
        require(addressToEpervierKey[intentAddress] == publicKeyAddress, "Address has no registered Epervier key");
        
        // EIGHTH: Conflict prevention: Check for other pending intents
        // Check for pending registration intents
        require(pendingIntents[intentAddress].timestamp == 0, "ETH Address has pending registration intent");
        require(pendingIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending registration intent");
        
        // Check for pending change intents
        require(changeETHAddressIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending change intent");
        
        // Check for pending unregistration intents
        require(unregistrationIntents[intentAddress].timestamp == 0, "ETH Address has pending unregistration intent");
        
        // Verify the ETH address from the message matches the intent address
        require(parsedEthAddress == intentAddress, "ETH Address mismatch in PQ message");
        
        // Verify the PQ nonce
        require(pqKeyNonces[publicKeyAddress] == parsedPQNonce, "ERR12: Invalid PQ nonce in submitUnregistrationIntent");
        
        // NINTH: Verify the ETH signature against the baseETHMessage
        // The ETH signature was created by signing the baseETHMessage with the Ethereum signed message prefix
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(baseETHMessage.length), baseETHMessage));
        
        // Debug logging
        emit DebugParseStep("baseETHMessage_length", baseETHMessage.length);
        emit DebugParseStep("ethSignedMessageHash", uint256(ethSignedMessageHash));
        emit DebugParseStep("eth_signature_v", v);
        emit DebugParseStep("eth_signature_r", uint256(r));
        emit DebugParseStep("eth_signature_s", uint256(s));
        
        // TENTH: Verify the ETH signature
        address ethSigner = ECDSA.recover(ethSignedMessageHash, v, r, s);
        emit DebugParseStep("recovered_eth_signer", uint256(uint160(ethSigner)));
        emit DebugParseStep("intent_address", uint256(uint160(intentAddress)));
        require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        // Store the unregistration intent
        unregistrationIntents[intentAddress] = UnregistrationIntent({
            publicKey: publicKey,
            publicKeyAddress: publicKeyAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp
        });
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        // Increment PQ nonce
        pqKeyNonces[publicKeyAddress]++;
        
        emit UnregistrationIntentSubmitted(intentAddress, publicKeyAddress);
    }
    
    /**
     * @dev Confirm unregistration with nested signatures
     * @param ethMessage The ETH message containing the PQ message and signature components
     * @param v The ETH signature v component
     * @param r The ETH signature r component
     * @param s The ETH signature s component
     */
    function confirmUnregistration(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // FIRST: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // SECOND: Parse PQ signature components from the ETH message
        bytes memory salt = MessageParser.extractPQSalt(ethMessage, 2);
        uint256[] memory cs1 = MessageParser.extractPQCs1(ethMessage, 2);
        uint256[] memory cs2 = MessageParser.extractPQCs2(ethMessage, 2);
        uint256 hint = MessageParser.extractPQHint(ethMessage, 2);
        bytes memory basePQMessage = MessageParser.extractBasePQMessage(ethMessage, 2);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // FOURTH: Parse the fingerprint address from the ETH message
        address fingerprintAddress = MessageParser.parseETHAddressFromETHUnregistrationConfirmationMessage(ethMessage);
        emit DebugParseStep("extracted_fingerprint_from_eth_message", uint256(uint160(fingerprintAddress)));
        emit DebugParseStep("recovered_pq_fingerprint", uint256(uint160(recoveredFingerprint)));
        require(fingerprintAddress == recoveredFingerprint, "Fingerprint address mismatch: ETH message vs recovered PQ signature");
        
        // FIFTH: Find the ETH address from the fingerprint using the bidirectional mapping
        address intentAddress = epervierKeyToAddress[recoveredFingerprint];
        require(intentAddress != address(0), "ETH Address not registered to PQ fingerprint");
        require(intentAddress == recoveredETHAddress, "ETH signature must be from registered address");
        
        // SIXTH: Check that there's a pending unregistration intent for this ETH Address
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found for ETH Address");
        
        // SEVENTH: Verify the public key matches the intent
        require(intent.publicKeyAddress == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // EIGHTH: Verify the ETH address from the base PQ message matches the intent address
        (address basePQEthAddress, ) = MessageParser.parseBasePQUnregistrationConfirmMessage(basePQMessage);
        emit DebugAddress("basePQEthAddress", basePQEthAddress);
        emit DebugAddress("intentAddress", intentAddress);
        // Print as bytes for byte-level comparison
        emit DebugParseStep("basePQEthAddress_uint", uint256(uint160(basePQEthAddress)));
        emit DebugParseStep("intentAddress_uint", uint256(uint160(intentAddress)));
        bytes20 basePQEthBytes = bytes20(basePQEthAddress);
        bytes20 intentAddrBytes = bytes20(intentAddress);
        for (uint i = 0; i < 20; i++) {
            emit DebugParseStep("basePQEthAddress_byte", uint8(basePQEthBytes[i]));
            emit DebugParseStep("intentAddress_byte", uint8(intentAddrBytes[i]));
        }
        require(basePQEthAddress == intentAddress, "ETH address mismatch: base PQ message vs intent address");
        
        // NINTH: Extract ETH nonce from the base PQ message
        uint256 ethNonce = MessageParser.extractEthNonce(basePQMessage, 1); // 1 for confirmation message
        
        // TENTH: Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "ERR11: Invalid ETH nonce in confirmUnregistration");
        
        // ELEVENTH: Verify PQ nonce from message
        uint256 pqNonce = MessageParser.extractPQNonce(basePQMessage, 0);
        emit DebugParseStep("extracted_pq_nonce", pqNonce);
        emit DebugParseStep("expected_pq_nonce", pqKeyNonces[recoveredFingerprint]);
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "ERR13: Invalid PQ nonce in confirmUnregistration");
        
        // TWELFTH: Verify the ETH message contains the correct confirmation text
        require(MessageParser.validateETHUnregistrationConfirmationMessage(ethMessage), "Invalid ETH confirmation message");
        
        // THIRTEENTH: Verify the PQ message contains the correct confirmation text
        require(MessageParser.validatePQUnregistrationConfirmationMessage(basePQMessage), "Invalid PQ confirmation message");
        
        // Remove the mappings
        epervierKeyToAddress[recoveredFingerprint] = address(0);
        addressToEpervierKey[intentAddress] = address(0);
        
        // Clear the intent
        delete unregistrationIntents[intentAddress];
        
        // Increment nonces
        ethNonces[intentAddress]++;
        pqKeyNonces[recoveredFingerprint]++;

        emit UnregistrationConfirmed(intentAddress, recoveredFingerprint);
    }
    
    /**
     * @dev Remove a pending unregistration intent
     * @param pqMessage The message signed by the PQ key (contains ETH Address and nonce)
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     */
    function removeUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        // Debug: Log the first 100 bytes of the message
        bytes memory first100 = new bytes(pqMessage.length < 100 ? pqMessage.length : 100);
        for (uint i = 0; i < first100.length; i++) {
            first100[i] = pqMessage[i];
        }
        emit DebugParseStep("pqMessage_first_100_bytes", uint256(keccak256(first100)));
        
        // FIRST: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Parse the ETH Address from the PQ message
        (address intentAddress, ) = MessageParser.parsePQRemoveUnregistrationIntentMessage(pqMessage);
        require(intentAddress != address(0), "Invalid intent address");
        
        // THIRD: Derive public key address from the recovered address
        address publicKeyAddress = recoveredFingerprint;
        
        // FOURTH: Check if there's a pending unregistration intent
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        
        // FIFTH: Verify the public key address matches the intent
        require(intent.publicKeyAddress == publicKeyAddress, "PQ key mismatch");
        
        // SIXTH: Verify the PQ message contains the correct removal text
        require(MessageParser.validatePQUnregistrationRemovalMessage(pqMessage), "Invalid PQ removal message");
        
        // SEVENTH: Clear the intent
        delete unregistrationIntents[intentAddress];

        emit UnregistrationIntentRemoved(intentAddress);
    }

    /**
     * @dev Extract base PQ message from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
     */
    function extractBasePQMessageFromPQMessage(bytes memory message) internal pure returns (bytes memory basePQMessage) {
        // Check if message is long enough to contain the pattern + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature
        require(message.length >= 32 + 35 + 20 + 15 + 20 + 32 + 65, "Message too short for base PQ message from PQ message");
        
        // Extract base PQ message (everything before the ETH signature)
        // Format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce
        uint256 baseMessageLength = 32 + 35 + 20 + 15 + 20 + 32; // DOMAIN_SEPARATOR + pattern + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce
        
        basePQMessage = new bytes(baseMessageLength);
        for (uint j = 0; j < baseMessageLength; j++) {
            basePQMessage[j] = message[j];
        }
        return basePQMessage;
    }

    /**
     * @dev Parse ETH Address from PQ remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function parseRemoveIntentAddress(bytes memory message) internal pure returns (address intentAddress) {
        // Look for the pattern "Remove intent from address " followed by an address
        bytes memory pattern = "Remove registration intent from ETH Address ";
        
        // Find the pattern in the message
        uint patternIndex = findPattern(message, pattern);
        if (patternIndex == type(uint).max) {
            return address(0);
        }
        
        // Extract the address (20 bytes after the pattern)
        uint addressStart = patternIndex + pattern.length;
        if (addressStart + 20 > message.length) {
            return address(0);
        }
        
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[addressStart + i];
        }
        
        return address(uint160(uint256(bytes32(addressBytes))));
    }
    
    /**
     * @dev Extract PQ nonce from remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function extractPQNonceFromRemoveMessage(bytes memory message) internal pure returns (uint256 pqNonce) {
        require(message.length >= 32 + 44 + 20 + 32, "Message too short for PQ nonce from remove message");
        
        // Extract the PQ nonce (last 32 bytes of the message)
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[message.length - 32 + j];
        }
        return abi.decode(nonceBytes, (uint256));
    }
    
    /**
     * @dev Validate that PQ message contains removal text for registration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + address + pqNonce
     */
    function validatePQRemoveIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove registration intent from ETH Address ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Remove a pending registration intent (PQ controlled)
     * @param pqMessage The PQ message containing the remove intent request
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     */
    function removeIntentByPQ(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        // FIRST: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Use the bidirectional mapping to find the ETH Address with pending intent
        address intentAddress = pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        require(intentAddress != address(0), "No pending intent found for this PQ fingerprint");
        
        // THIRD: Comprehensive cross-reference validation
        // 1. Check if there's a pending intent for the referenced ETH Address
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for referenced ETH Address");
        
        // 2. Verify the recovered PQ fingerprint matches the stored intent
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        
        // 3. Verify the bidirectional mapping is consistent
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] == intentAddress, "Bidirectional mapping mismatch");
        
        // FOURTH: Extract PQ nonce from the PQ message
        uint256 pqNonce = MessageParser.extractPQNonceFromRemoveMessage(pqMessage);
        
        // FIFTH: Verify PQ nonce
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // SIXTH: Verify the PQ message contains the correct removal text
        require(MessageParser.validatePQRemoveIntentMessage(pqMessage), "Invalid PQ removal message");
        
        // Clear both mappings
        delete pendingIntents[intentAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // Increment PQ nonce
        pqKeyNonces[recoveredFingerprint]++;
        
        emit RegistrationIntentRemoved(intentAddress);
    }

    /**
     * @dev Parse ETH Address from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
     */
    function parseETHAddressFromConfirmMessage(bytes memory message) internal pure returns (address ethAddress) {
        // Check if message is long enough to contain the pattern + ethAddress
        require(message.length >= 32 + 35 + 20, "Message too short for ETH Address from confirm message");
        
        // Extract the ETH Address (20 bytes after DOMAIN_SEPARATOR + "Confirm binding ETH Address ")
        bytes memory addressBytes = new bytes(20);
        for (uint j = 0; j < 20; j++) {
            addressBytes[j] = message[32 + 35 + j]; // DOMAIN_SEPARATOR + pattern + offset
        }
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        return address(uint160(addr));
    }

    /**
     * @dev Parse fingerprint address from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
     */
    function parseFingerprintFromConfirmMessage(bytes memory message) internal pure returns (address fingerprintAddress) {
        // Check if message is long enough to contain the pattern + ethAddress + " to Fingerprint " + fingerprintAddress
        require(message.length >= 32 + 35 + 20 + 15 + 20, "Message too short for fingerprint from confirm message");
        
        // Extract the fingerprint address (20 bytes after DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint ")
        bytes memory addressBytes = new bytes(20);
        for (uint j = 0; j < 20; j++) {
            addressBytes[j] = message[32 + 35 + 20 + 15 + j]; // DOMAIN_SEPARATOR + pattern + ethAddress + " to Fingerprint " + offset
        }
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        return address(uint160(addr));
    }

    // ============ UNIFIED MESSAGE PARSING HELPER ============
    
    /**
     * @dev Unified message parser that can handle all message types from our schema
     * @param message The message to parse
     * @param expectedPattern The expected pattern to find in the message
     * @param patternLength The length of the expected pattern
     * @param fieldOffsets Array of field offsets from the start of the message
     * @param fieldLengths Array of field lengths
     * @param fieldTypes Array of field types ("address", "uint256", "bytes", "uint8", "bytes32")
     * @return parsedFields Array of parsed field values as bytes
     */
    function parseMessageFields(
        bytes memory message,
        bytes memory expectedPattern,
        uint256 patternLength,
        uint256[] memory fieldOffsets,
        uint256[] memory fieldLengths,
        string[] memory fieldTypes
    ) internal returns (bytes[] memory parsedFields) {
        require(fieldOffsets.length == fieldLengths.length, "Field offsets and lengths must match");
        require(fieldOffsets.length == fieldTypes.length, "Field offsets and types must match");
        emit DebugParseStep("parseMessageFields_pattern_length", patternLength);
        emit DebugParseStep("parseMessageFields_message_length", message.length);
        // Print the first 60 bytes after DOMAIN_SEPARATOR
        for (uint i = 32; i < 92 && i < message.length; i++) {
            emit DebugParseStep("parseMessageFields_message_byte", uint8(message[i]));
        }
        for (uint i = 0; i < expectedPattern.length; i++) {
            emit DebugParseStep("parseMessageFields_pattern_byte", uint8(expectedPattern[i]));
        }
        uint256 patternIndex = findPattern(message, expectedPattern, true); // Skip DOMAIN_SEPARATOR
        emit DebugParseStep("parseMessageFields_pattern_found_at", patternIndex);
        require(patternIndex != type(uint256).max, "Expected pattern not found in message");
        parsedFields = new bytes[](fieldOffsets.length);
        for (uint256 i = 0; i < fieldOffsets.length; i++) {
            uint256 actualFieldStart = patternIndex + patternLength + (fieldOffsets[i] - (32 + patternLength));
            uint256 fieldLength = fieldLengths[i];
            require(actualFieldStart + fieldLength <= message.length, "Field extends beyond message length");
            parsedFields[i] = new bytes(fieldLength);
            for (uint256 j = 0; j < fieldLength; j++) {
                parsedFields[i][j] = message[actualFieldStart + j];
            }
        }
        return parsedFields;
    }
    
    /**
     * @dev Parse a BasePQRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce
     */
    function parseBasePQRegistrationIntentMessage(bytes memory message) public returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Intent to pair ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59
        fieldOffsets[0] = 59;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 59 + 20 = 79
        fieldOffsets[1] = 79;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert bytes to address and uint256
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse an ETHRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHRegistrationIntentMessage(bytes memory message) internal returns (
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Intent to pair Epervier Key";
        uint256[] memory fieldOffsets = new uint256[](6);
        uint256[] memory fieldLengths = new uint256[](6);
        string[] memory fieldTypes = new string[](6);
        
        // basePQMessage: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59, length = 111
        fieldOffsets[0] = 59;
        fieldLengths[0] = 111;
        fieldTypes[0] = "bytes";
        
        // salt: starts after basePQMessage = 59 + 111 = 170, length = 40
        fieldOffsets[1] = 170;
        fieldLengths[1] = 40;
        fieldTypes[1] = "bytes";
        
        // cs1: starts after salt = 170 + 40 = 210, length = 32 * 32 = 1024
        fieldOffsets[2] = 210;
        fieldLengths[2] = 1024;
        fieldTypes[2] = "uint256[32]";
        
        // cs2: starts after cs1 = 210 + 1024 = 1234, length = 32 * 32 = 1024
        fieldOffsets[3] = 1234;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // hint: starts after cs2 = 1234 + 1024 = 2258, length = 32
        fieldOffsets[4] = 2258;
        fieldLengths[4] = 32;
        fieldTypes[4] = "uint256";
        
        // ethNonce: starts after hint = 2258 + 32 = 2290, length = 32
        fieldOffsets[5] = 2290;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        basePQMessage = parsedFields[0];
        salt = parsedFields[1];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[2][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[3][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[4]));
        ethNonce = uint256(bytes32(parsedFields[5]));
    }
    
    /**
     * @dev Parse a BaseETHRegistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function parseBaseETHRegistrationConfirmationMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Confirm bonding to Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (40) = 72
        fieldOffsets[0] = 72;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 72 + 20 = 92
        fieldOffsets[1] = 92;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 40, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRegistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQRegistrationConfirmationMessage(bytes memory message) public returns (
        address ethAddress,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm binding ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](6);
        uint256[] memory fieldLengths = new uint256[](6);
        string[] memory fieldTypes = new string[](6);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (28) = 60
        fieldOffsets[0] = 60;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // baseETHMessage: starts after ethAddress = 60 + 20 = 80, length = 124
        fieldOffsets[1] = 80;
        fieldLengths[1] = 124;
        fieldTypes[1] = "bytes";
        
        // v: starts after baseETHMessage = 80 + 124 = 204, length = 1
        fieldOffsets[2] = 204;
        fieldLengths[2] = 1;
        fieldTypes[2] = "uint8";
        
        // r: starts after v = 204 + 1 = 205, length = 32
        fieldOffsets[3] = 205;
        fieldLengths[3] = 32;
        fieldTypes[3] = "bytes32";
        
        // s: starts after r = 205 + 32 = 237, length = 32
        fieldOffsets[4] = 237;
        fieldLengths[4] = 32;
        fieldTypes[4] = "bytes32";
        
        // pqNonce: starts after s = 237 + 32 = 269, length = 32
        fieldOffsets[5] = 269;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 28, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        baseETHMessage = parsedFields[1];
        v = uint8(parsedFields[2][0]);
        r = bytes32(parsedFields[3]);
        s = bytes32(parsedFields[4]);
        pqNonce = uint256(bytes32(parsedFields[5]));
    }
    
    /**
     * @dev Parse an ETHRemoveIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address" + pqFingerprint + ethNonce
     */
    function parseETHRemoveIntentMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove intent from address";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (39) = 71
        fieldOffsets[0] = 71;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 71 + 20 = 91
        fieldOffsets[1] = 91;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 39, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + ethAddress + pqNonce
     */
    function parsePQRemoveIntentMessage(bytes memory message) internal returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove intent from address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59
        fieldOffsets[0] = 59;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 59 + 20 = 79
        fieldOffsets[1] = 79;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }

    /**
     * @dev Parse a BaseETHChangeETHAddressIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
     */
    function parseBaseETHChangeETHAddressIntentMessage(bytes memory message) internal returns (
        address pqFingerprint,
        address newEthAddress,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](4);
        uint256[] memory fieldLengths = new uint256[](4);
        string[] memory fieldTypes = new string[](4);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (64) = 96
        fieldOffsets[0] = 96;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after pqFingerprint = 96 + 20 = 116, length = 4
        fieldOffsets[1] = 116;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 116 + 4 = 120, length = 20
        fieldOffsets[2] = 120;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // ethNonce: starts after newEthAddress = 120 + 20 = 140, length = 32
        fieldOffsets[3] = 140;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 64, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to addresses manually to ensure correct byte order
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr1));
        
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(parsedFields[2][j]);
        }
        newEthAddress = address(uint160(addr2));
        ethNonce = uint256(bytes32(parsedFields[3]));
    }
    
    /**
     * @dev Parse a PQChangeETHAddressIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQChangeETHAddressIntentMessage(bytes memory message) internal returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        bytes memory pattern = "Intent to change bound ETH Address from ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // oldEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (40) = 72
        fieldOffsets[0] = 72;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 72 + 20 = 92, length = 4
        fieldOffsets[1] = 92;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 92 + 4 = 96, length = 20
        fieldOffsets[2] = 96;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // baseETHMessage: starts after newEthAddress = 96 + 20 = 116, length = 172
        fieldOffsets[3] = 116;
        fieldLengths[3] = 172;
        fieldTypes[3] = "bytes";
        
        // v: starts after baseETHMessage = 116 + 172 = 288, length = 1
        fieldOffsets[4] = 288;
        fieldLengths[4] = 1;
        fieldTypes[4] = "uint8";
        
        // r: starts after v = 288 + 1 = 289, length = 32
        fieldOffsets[5] = 289;
        fieldLengths[5] = 32;
        fieldTypes[5] = "bytes32";
        
        // s: starts after r = 289 + 32 = 321, length = 32
        fieldOffsets[6] = 321;
        fieldLengths[6] = 32;
        fieldTypes[6] = "bytes32";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 40, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to addresses manually to ensure correct byte order
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(parsedFields[0][j]);
        }
        oldEthAddress = address(uint160(addr1));
        
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(parsedFields[2][j]);
        }
        newEthAddress = address(uint160(addr2));
        
        baseETHMessage = parsedFields[3];
        v = uint8(parsedFields[4][0]);
        r = bytes32(parsedFields[5]);
        s = bytes32(parsedFields[6]);
        
        // Extract pqNonce from the end of the message (last 32 bytes)
        bytes memory pqNonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            pqNonceBytes[j] = message[message.length - 32 + j];
        }
        pqNonce = uint256(bytes32(pqNonceBytes));
    }
    
    /**
     * @dev Parse a BasePQChangeETHAddressConfirmMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing bound ETH Address for Epervier Fingerprint from " + oldEthAddress + " to " + newEthAddress + pqNonce
     */
    function parseBasePQChangeETHAddressConfirmMessage(bytes memory message) internal returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm changing bound ETH Address for Epervier Fingerprint from ";
        uint256[] memory fieldOffsets = new uint256[](4);
        uint256[] memory fieldLengths = new uint256[](4);
        string[] memory fieldTypes = new string[](4);
        
        // oldEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (65) = 97
        fieldOffsets[0] = 97;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 97 + 20 = 117, length = 4
        fieldOffsets[1] = 117;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 117 + 4 = 121, length = 20
        fieldOffsets[2] = 121;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // pqNonce: starts after newEthAddress = 121 + 20 = 141, length = 32
        fieldOffsets[3] = 141;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 65, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to addresses manually to ensure correct byte order
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(parsedFields[0][j]);
        }
        oldEthAddress = address(uint160(addr1));
        
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(parsedFields[2][j]);
        }
        newEthAddress = address(uint160(addr2));
        pqNonce = uint256(bytes32(parsedFields[3]));
    }
    
    /**
     * @dev Parse a BaseETHUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from PQ fingerprint" + pqFingerprint + ethNonce
     */
    function parseBaseETHUnregistrationIntentMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to unregister from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (47) = 79
        fieldOffsets[0] = 79;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 79 + 20 = 99
        fieldOffsets[1] = 99;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQUnregistrationIntentMessage(bytes memory message) internal returns (
        address currentEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        // Schema-based offsets (from pqregistry_message_schema.json)
        // DOMAIN_SEPARATOR: 32 bytes
        // pattern: 60 bytes ("Intent to unregister from Epervier Fingerprint from address ")
        // currentEthAddress: 20 bytes (offset 92)
        // baseETHMessage: 131 bytes (offset 112)
        // v: 1 byte (offset 243)
        // r: 32 bytes (offset 244)
        // s: 32 bytes (offset 276)
        // pqNonce: 32 bytes (offset 308)
        
        require(message.length >= 340, "Message too short for PQUnregistrationIntentMessage");
        
        // Extract ETH address (offset 92, length 20)
        bytes memory addrBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addrBytes[i] = message[92 + i];
        }
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addrBytes[j]);
        }
        currentEthAddress = address(uint160(addr));
        
        // Extract baseETHMessage (offset 112, length 131)
        baseETHMessage = new bytes(131);
        for (uint i = 0; i < 131; i++) {
            baseETHMessage[i] = message[112 + i];
        }
        
        // Extract v (offset 243, length 1)
        v = uint8(message[243]);
        
        // Extract r (offset 244, length 32)
        bytes memory rBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            rBytes[i] = message[244 + i];
        }
        r = bytes32(rBytes);
        
        // Extract s (offset 276, length 32)
        bytes memory sBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            sBytes[i] = message[276 + i];
        }
        s = bytes32(sBytes);
        
        // Extract pqNonce (offset 308, length 32)
        bytes memory nonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            nonceBytes[i] = message[308 + i];
        }
        pqNonce = uint256(bytes32(nonceBytes));
    }
    
    
    /**
     * @dev Parse a BasePQUnregistrationConfirmMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
     */
    function parseBasePQUnregistrationConfirmMessage(bytes memory message) internal returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm unregistration from ETH Address ";
        emit DebugParseStep("parseBasePQUnregistrationConfirmMessage_message_length", message.length);
        emit DebugParseStep("parseBasePQUnregistrationConfirmMessage_pattern_length", pattern.length);
        
        uint256 manualPatternIndex = type(uint256).max;
        for (uint i = 32; i <= message.length - pattern.length; i++) {
            bool found = true;
            for (uint j = 0; j < pattern.length; j++) {
                if (message[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                manualPatternIndex = i;
                break;
            }
        }
        require(manualPatternIndex != type(uint256).max, "Pattern not found");
        
        // Calculate field offsets
        uint256 ethAddressStart = manualPatternIndex + pattern.length;
        uint256 ethAddressEnd = ethAddressStart + 20;
        uint256 pqNonceStart = ethAddressEnd;
        uint256 pqNonceEnd = pqNonceStart + 32;
        
        emit DebugParseStep("ethAddressStart", ethAddressStart);
        emit DebugParseStep("ethAddressEnd", ethAddressEnd);
        emit DebugParseStep("pqNonceStart", pqNonceStart);
        emit DebugParseStep("pqNonceEnd", pqNonceEnd);
        emit DebugParseStep("message_length_for_check", message.length);
        
        require(pqNonceEnd <= message.length, "Message too short for pqNonce");
        
        // Extract ethAddress
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[ethAddressStart + i];
        }
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        ethAddress = address(uint160(addr));
        
        // Extract pqNonce
        bytes memory nonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            nonceBytes[i] = message[pqNonceStart + i];
        }
        pqNonce = uint256(bytes32(nonceBytes));
    }
    
    /**
     * @dev Parse an ETHUnregistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHUnregistrationConfirmationMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (49) = 81
        fieldOffsets[0] = 81;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 81 + 20 = 101, length = 111
        fieldOffsets[1] = 101;
        fieldLengths[1] = 111;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 101 + 111 = 212, length = 40
        fieldOffsets[2] = 212;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 212 + 40 = 252, length = 32 * 32 = 1024
        fieldOffsets[3] = 252;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 252 + 1024 = 1276, length = 32 * 32 = 1024
        fieldOffsets[4] = 1276;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1276 + 1024 = 2300, length = 32
        fieldOffsets[5] = 2300;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2300 + 32 = 2332, length = 32
        fieldOffsets[6] = 2332;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 49, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        basePQMessage = parsedFields[1];
        salt = parsedFields[2];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[3][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[4][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[5]));
        ethNonce = uint256(bytes32(parsedFields[6]));
    }

    /**
     * @dev Parse an ETHRemoveRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function parseETHRemoveRegistrationIntentMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove registration intent from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (53) = 85
        fieldOffsets[0] = 85;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 85 + 20 = 105
        fieldOffsets[1] = 105;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 53, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse an ETHRemoveChangeIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function parseETHRemoveChangeIntentMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove change intent from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (47) = 79
        fieldOffsets[0] = 79;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 79 + 20 = 99
        fieldOffsets[1] = 99;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + ethAddress + pqNonce
     */
    function parsePQRemoveRegistrationIntentMessage(bytes memory message) internal returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove registration intent from ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (44) = 76
        fieldOffsets[0] = 76;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        // pqNonce: starts after ethAddress = 76 + 20 = 96
        fieldOffsets[1] = 96;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 44, fieldOffsets, fieldLengths, fieldTypes);
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveChangeIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
     */
    function parsePQRemoveChangeIntentMessage(bytes memory message) internal returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove change intent from ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (38) = 70
        fieldOffsets[0] = 70;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 70 + 20 = 90
        fieldOffsets[1] = 90;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 38, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce
     */
    function parsePQRemoveUnregistrationIntentMessage(bytes memory message) internal returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove unregistration intent from ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (46) = 78
        fieldOffsets[0] = 78;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 78 + 20 = 98
        fieldOffsets[1] = 98;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 46, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }

    /**
     * @dev Parse a ETHChangeETHAddressIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHChangeETHAddressIntentMessage(bytes memory message) internal returns (
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (52) = 84
        fieldOffsets[0] = 84;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 84 + 20 = 104, length = 173
        fieldOffsets[1] = 104;
        fieldLengths[1] = 173;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 104 + 173 = 277, length = 40
        fieldOffsets[2] = 277;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 277 + 40 = 317, length = 32 * 32 = 1024
        fieldOffsets[3] = 317;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 317 + 1024 = 1341, length = 32 * 32 = 1024
        fieldOffsets[4] = 1341;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1341 + 1024 = 2365, length = 32
        fieldOffsets[5] = 2365;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2365 + 32 = 2397, length = 32
        fieldOffsets[6] = 2397;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 52, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        // Note: pqFingerprint is parsed but not returned as it's not needed for this function
        basePQMessage = parsedFields[1];
        salt = parsedFields[2];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[3][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[4][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[5]));
        ethNonce = uint256(bytes32(parsedFields[6]));
    }

    /**
     * @dev Parse a ETHChangeETHAddressConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address for Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHChangeETHAddressConfirmationMessage(bytes memory message) internal returns (
        address pqFingerprint,
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Confirm change ETH Address for Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (52) = 84
        fieldOffsets[0] = 84;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 84 + 20 = 104, length = 173
        fieldOffsets[1] = 104;
        fieldLengths[1] = 173;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 104 + 173 = 277, length = 40
        fieldOffsets[2] = 277;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 277 + 40 = 317, length = 32 * 32 = 1024
        fieldOffsets[3] = 317;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 317 + 1024 = 1341, length = 32 * 32 = 1024
        fieldOffsets[4] = 1341;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1341 + 1024 = 2365, length = 32
        fieldOffsets[5] = 2365;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2365 + 32 = 2397, length = 32
        fieldOffsets[6] = 2397;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 52, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        
        basePQMessage = parsedFields[1];
        salt = parsedFields[2];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[3][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[4][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[5]));
        ethNonce = uint256(bytes32(parsedFields[6]));
    }

    function removeChangeETHAddressIntentByPQ(
        bytes memory pqMessage,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint
    ) external {
        // Verify PQ signature
        address pqFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(pqFingerprint != address(0), "Invalid PQ signature");

        // Parse the PQ remove change intent message
        // Format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
        bytes memory domainSeparator = abi.encodePacked(keccak256("PQRegistry"));
        bytes memory pattern = "Remove change intent from ETH Address ";
        
        require(pqMessage.length >= domainSeparator.length + pattern.length + 20 + 32, "Invalid message length");
        
        // Extract ETH address and PQ nonce
        uint256 ethAddressStart = domainSeparator.length + pattern.length;
        
        // Extract ETH address (20 bytes)
        bytes memory ethAddressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            ethAddressBytes[i] = pqMessage[ethAddressStart + i];
        }
        
        // Convert bytes to address properly
        uint256 addr = 0;
        for (uint i = 0; i < 20; i++) {
            addr = (addr << 8) | uint8(ethAddressBytes[i]);
        }
        address ethAddress = address(uint160(addr));
        
        // Extract PQ nonce (last 32 bytes)
        bytes memory nonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            nonceBytes[i] = pqMessage[pqMessage.length - 32 + i];
        }
        uint256 pqNonce = uint256(bytes32(nonceBytes));
        
        // Debug: Log extracted values
        emit DebugParseStep("extracted_pq_nonce", pqNonce);
        emit DebugParseStep("current_pq_nonce", pqKeyNonces[pqFingerprint]);
        emit DebugParseStep("extracted_eth_address", uint256(uint160(ethAddress)));
        emit DebugParseStep("changeETHAddressIntents[pqFingerprint].newETHAddress", uint256(uint160(changeETHAddressIntents[pqFingerprint].newETHAddress)));
        
        // Additional debug: Log addresses in hex format
        emit DebugParseStep("extracted_eth_address_hex", uint256(uint160(ethAddress)));
        emit DebugParseStep("intent_new_eth_address_hex", uint256(uint160(changeETHAddressIntents[pqFingerprint].newETHAddress)));
        
        // Verify ETH address is registered to this PQ fingerprint
        require(epervierKeyToAddress[pqFingerprint] == ethAddress, "ETH address not registered to PQ fingerprint");
        
        // Verify there's a pending change intent
        ChangeETHAddressIntent memory intent = changeETHAddressIntents[pqFingerprint];
        require(intent.newETHAddress != address(0), "No pending change intent");
        require(intent.timestamp > 0, "No pending change intent");
        
        // Verify PQ nonce
        require(pqKeyNonces[pqFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // Clear the change intent
        delete changeETHAddressIntents[pqFingerprint];
        
        // Increment PQ nonce
        pqKeyNonces[pqFingerprint]++;
        
        emit ChangeETHAddressIntentRemoved(pqFingerprint);
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
     * @dev Parse ETH Address from PQ unregistration intent message
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + ethAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQRemoveUnregistrationIntentAddress(bytes memory message) internal pure returns (address intentAddress) {
        // Check if message is long enough to contain the pattern + address + baseETHMessage + signature + nonce
        if (message.length < 32 + 60 + 20) { // DOMAIN_SEPARATOR + pattern + address (minimum)
            return address(0);
        }
        
        // Create the pattern to search for: "Intent to unregister from Epervier Fingerprint from address "
        bytes memory keyPattern = new bytes(60);
        keyPattern[0] = 0x49; // 'I'
        keyPattern[1] = 0x6e; // 'n'
        keyPattern[2] = 0x74; // 't'
        keyPattern[3] = 0x65; // 'e'
        keyPattern[4] = 0x6e; // 'n'
        keyPattern[5] = 0x74; // 't'
        keyPattern[6] = 0x20; // ' '
        keyPattern[7] = 0x74; // 't'
        keyPattern[8] = 0x6f; // 'o'
        keyPattern[9] = 0x20; // ' '
        keyPattern[10] = 0x75; // 'u'
        keyPattern[11] = 0x6e; // 'n'
        keyPattern[12] = 0x72; // 'r'
        keyPattern[13] = 0x65; // 'e'
        keyPattern[14] = 0x67; // 'g'
        keyPattern[15] = 0x69; // 'i'
        keyPattern[16] = 0x73; // 's'
        keyPattern[17] = 0x74; // 't'
        keyPattern[18] = 0x65; // 'e'
        keyPattern[19] = 0x72; // 'r'
        keyPattern[20] = 0x20; // ' '
        keyPattern[21] = 0x66; // 'f'
        keyPattern[22] = 0x72; // 'r'
        keyPattern[23] = 0x6f; // 'o'
        keyPattern[24] = 0x6d; // 'm'
        keyPattern[25] = 0x20; // ' '
        keyPattern[26] = 0x45; // 'E'
        keyPattern[27] = 0x70; // 'p'
        keyPattern[28] = 0x65; // 'e'
        keyPattern[29] = 0x72; // 'r'
        keyPattern[30] = 0x76; // 'v'
        keyPattern[31] = 0x69; // 'i'
        keyPattern[32] = 0x65; // 'e'
        keyPattern[33] = 0x72; // 'r'
        keyPattern[34] = 0x20; // ' '
        keyPattern[35] = 0x46; // 'F'
        keyPattern[36] = 0x69; // 'i'
        keyPattern[37] = 0x6e; // 'n'
        keyPattern[38] = 0x67; // 'g'
        keyPattern[39] = 0x65; // 'e'
        keyPattern[40] = 0x72; // 'r'
        keyPattern[41] = 0x70; // 'p'
        keyPattern[42] = 0x72; // 'r'
        keyPattern[43] = 0x69; // 'i'
        keyPattern[44] = 0x6e; // 'n'
        keyPattern[45] = 0x74; // 't'
        keyPattern[46] = 0x20; // ' '
        keyPattern[47] = 0x66; // 'f'
        keyPattern[48] = 0x72; // 'r'
        keyPattern[49] = 0x6f; // 'o'
        keyPattern[50] = 0x6d; // 'm'
        keyPattern[51] = 0x20; // ' '
        keyPattern[52] = 0x61; // 'a'
        keyPattern[53] = 0x64; // 'd'
        keyPattern[54] = 0x64; // 'd'
        keyPattern[55] = 0x72; // 'r'
        keyPattern[56] = 0x65; // 'e'
        keyPattern[57] = 0x73; // 's'
        keyPattern[58] = 0x73; // 's'
        keyPattern[59] = 0x20; // ' '
        
        // Start searching after the DOMAIN_SEPARATOR (offset 32)
        uint startOffset = 32;
        uint maxSearchIndex = message.length - 80; // 60 bytes pattern + 20 bytes address (minimum)
        
        for (uint i = startOffset; i <= maxSearchIndex; i++) {
            bool found = true;
            for (uint j = 0; j < 60; j++) {
                if (message[i + j] != keyPattern[j]) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                // Extract the next 20 bytes as the address
                bytes memory addressBytes = new bytes(20);
                for (uint j = 0; j < 20; j++) {
                    addressBytes[j] = message[i + 60 + j]; // Skip the "Intent to unregister from Epervier Fingerprint from address " pattern
                }
                
                // Convert bytes to address
                uint256 addr = 0;
                for (uint j = 0; j < 20; j++) {
                    addr = (addr << 8) | uint8(addressBytes[j]);
                }
                return address(uint160(addr));
            }
        }
        
        return address(0);
    }

    /**
     * @dev Parse ETH Address from ETH unregistration confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + fingerprintAddress + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHAddressFromETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (address fingerprintAddress) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        uint startOffset = 32; // Skip DOMAIN_SEPARATOR
        uint patternIndex = findPattern(message, pattern, true); // true = skip DOMAIN_SEPARATOR
        if (patternIndex == type(uint).max) {
            return address(0);
        }
        uint addressStart = patternIndex + pattern.length;
        if (addressStart + 20 > message.length) {
            return address(0);
        }
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[addressStart + i];
        }
        // Manual conversion to address (big-endian)
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        return address(uint160(addr));
    }
}
