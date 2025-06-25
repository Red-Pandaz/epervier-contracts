// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
// TODO: Add a function that allows ETH address to remove ChangeEThAddressIntent
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
    
    // Nonces for ETH addresses (per domain)
    mapping(address => uint256) public ethNonces;
    
    // Nonces for PQ keys (existing)
    mapping(address => uint256) public pqKeyNonces;
    
    // Pending intents for two-step registration - ETH address controls their intent
    struct Intent {
        address pqFingerprint;
        bytes intentMessage;
        uint256 timestamp;
    }
    mapping(address => Intent) public pendingIntents;
    
    // Bidirectional mapping: PQ fingerprint to ETH address with pending intent
    mapping(address => address) public pqFingerprintToPendingIntentAddress;
    
    // Pending change ETH address intents - PQ key controls their intent
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
     * @dev Extract ETH nonce from PQ message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature
     */
    function extractEthNonce(bytes memory message) internal pure returns (uint256 ethNonce) {
        // Check if message is long enough to contain the pattern + address + nonce + signature
        require(message.length >= 32 + 27 + 20 + 32 + 65, "Message too short for ETH nonce");
        
        // Extract the ETH nonce (32 bytes before the ETH signature)
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[message.length - 65 - 32 + j];
        }
        return abi.decode(nonceBytes, (uint256));
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
            // ChangeETHAddress: "Confirm change ETH Address" (27 bytes)
            patternLength = 27;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration" (23 bytes)
            patternLength = 23;
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
            patternLength = 27;
        } else if (messageType == 2) {
            patternLength = 23;
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
            patternLength = 27;
        } else if (messageType == 2) {
            patternLength = 23;
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
            patternLength = 27;
        } else if (messageType == 2) {
            patternLength = 23;
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
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 27;
        } else if (messageType == 2) {
            patternLength = 23;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2 + hint
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32 + 32*32 + 32, "Message too short for base PQ message");
        
        // Extract base PQ message (everything after hint)
        uint256 baseMessageStart = 32 + patternLength + 32 + 40 + 32*32 + 32*32 + 32; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + cs2 + hint
        uint256 baseMessageLength = message.length - baseMessageStart;
        
        basePQMessage = new bytes(baseMessageLength);
        for (uint j = 0; j < baseMessageLength; j++) {
            basePQMessage[j] = message[baseMessageStart + j];
        }
        return basePQMessage;
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
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to epervier fingerprint " + fingerprint + ethNonce
     */
    function extractFingerprintFromETHMessage(bytes memory message) internal pure returns (address fingerprint) {
        require(message.length >= 32 + 40 + 20 + 32, "Message too short for fingerprint from ETH message");
        bytes memory fingerprintBytes = new bytes(20);
        for (uint j = 0; j < 20; j++) {
            fingerprintBytes[j] = message[32 + 40 + j]; // DOMAIN_SEPARATOR + "Confirm bonding to epervier fingerprint " + offset
        }
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(fingerprintBytes[j]);
        }
        return address(uint160(addr));
    }

    /**
     * @dev Parse current ETH address from change address message
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
     * @dev Parse new ETH address from change address message
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
     */
    function findPattern(bytes memory data, bytes memory pattern) internal pure returns (uint index) {
        if (pattern.length > data.length) {
            return type(uint).max;
        }
        
        for (uint i = 0; i <= data.length - pattern.length; i++) {
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
     * @dev Validate that ETH message contains confirmation text for changing ETH address
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address" + ethNonce + pqMessage
     */
    function validateETHConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm change ETH Address";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for changing ETH address
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing ETH address from " + currentAddress + " to " + newAddress + pqNonce
     */
    function validatePQConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm changing ETH address from ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for change ETH address intent
     * Expected format: DOMAIN_SEPARATOR + "Remove change ETH address intent" + currentAddress + pqNonce
     */
    function validatePQRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove change ETH address intent";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from PQ fingerprint" + ethNonce + pqMessage
     */
    function validateETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from PQ fingerprint";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from PQ fingerprint" + ethAddress + pqNonce
     */
    function validatePQUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from PQ fingerprint";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for unregistration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent" + pqNonce
     */
    function validatePQUnregistrationRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove unregistration intent";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Extract ETH nonce from ETH message
     * @param message The message to extract nonce from
     * @param messageType 0 for intent message, 1 for confirmation message
     * Intent format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     * Confirmation format: DOMAIN_SEPARATOR + "Confirm bonding to epervier fingerprint " + fingerprint + ethNonce
     */
    function extractEthNonce(bytes memory message, uint8 messageType) internal pure returns (uint256 ethNonce) {
        if (messageType == 0) {
            // Intent message format
            require(message.length >= 32 + 27 + 32, "Message too short for ETH nonce from intent message");
            
            // Extract the ETH nonce (32 bytes after DOMAIN_SEPARATOR + pattern)
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[32 + 27 + j]; // DOMAIN_SEPARATOR + pattern + offset
            }
            return abi.decode(nonceBytes, (uint256));
        } else if (messageType == 1) {
            // Confirmation message format: DOMAIN_SEPARATOR + "Confirm bonding to epervier fingerprint " + fingerprint + ethNonce
            require(message.length >= 32 + 40 + 20 + 32, "Message too short for ETH nonce from confirmation message");
            
            // Extract the ETH nonce (last 32 bytes of the message)
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j]; // Last 32 bytes
            }
            
            // Convert bytes to uint256 manually to ensure correct byte order
            uint256 nonce = 0;
            for (uint j = 0; j < 32; j++) {
                nonce = (nonce << 8) | uint8(nonceBytes[j]);
            }
            return nonce;
        } else {
            revert("Invalid message type");
        }
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
        ) = parseETHRegistrationIntentMessage(ethMessage);
        
        // Debug logging for extracted components
        emit DebugParseStep("extracted_hint", hint);
        emit DebugParseStep("salt_length", salt.length);
        emit DebugParseStep("cs1_length", cs1.length);
        emit DebugParseStep("cs2_length", cs2.length);
        emit DebugParseStep("base_pq_message_length", basePQMessage.length);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated during confirmation by comparing fingerprints
        
        // FOURTH: Parse the base PQ message using our standardized schema
        (address intentAddress, uint256 pqNonce) = parseBasePQRegistrationIntentMessage(basePQMessage);
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
        require(unregistrationIntents[intentAddress].timestamp == 0, "ETH address has pending unregistration intent");
        
        // Store the intent with the recovered fingerprint address directly
        pendingIntents[intentAddress] = Intent({
            pqFingerprint: recoveredFingerprint,  // Use recovered address directly
            intentMessage: basePQMessage,
            timestamp: block.timestamp
        });
        
        // Store the bidirectional mapping: PQ fingerprint to ETH address
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
        ) = parsePQRegistrationConfirmationMessage(pqMessage);
        
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
        (address pqFingerprint, uint256 ethNonce) = parseBaseETHRegistrationConfirmationMessage(baseETHMessage);
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. ETH address from PQ message must match recovered ETH address from ETH signature
        require(ethAddress == recoveredETHAddress, "ETH address mismatch: PQ message vs recovered ETH signature");
        
        // 2. PQ fingerprint from ETH message must match recovered PQ fingerprint from PQ signature
        require(pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // 3. Check that there's a pending intent for this ETH address
        Intent storage intent = pendingIntents[ethAddress];
        require(intent.timestamp != 0, "No pending intent found for ETH address");
        
        // 4. ETH address from PQ message must match the stored intent ETH address
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] == ethAddress, "ETH address mismatch: PQ message vs stored intent");
        
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
        (address pqFingerprint, uint256 ethNonce) = parseETHRemoveRegistrationIntentMessage(ethMessage);
        
        // THIRD: Comprehensive cross-reference validation
        // 1. Check if there's a pending intent for the recovered ETH address
        Intent storage intent = pendingIntents[recoveredETHAddress];
        require(intent.timestamp != 0, "No pending intent found for recovered ETH address");
        
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
     * @dev Remove a pending change ETH address intent (ETH controlled)
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
        (address pqFingerprint, uint256 ethNonce) = parseETHRemoveChangeIntentMessage(ethMessage);
        
        // THIRD: Comprehensive cross-reference validation
        // 1. Check if there's a pending change intent for this PQ fingerprint
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[pqFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        
        // 2. Verify the ETH address from the message matches the current registration
        require(addressToEpervierKey[recoveredETHAddress] == pqFingerprint, "ETH address not registered to PQ fingerprint");
        
        // 3. Verify the PQ fingerprint is currently registered to the ETH address
        require(epervierKeyToAddress[pqFingerprint] == recoveredETHAddress, "PQ fingerprint not registered to ETH address");
        
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
        
        // SECOND: Parse the ETH change address intent message using our standardized schema
        (
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = parseETHChangeETHAddressConfirmationMessage(ethMessage);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // FOURTH: Parse the base PQ change address intent message using our standardized schema
        (address oldEthAddress, address newEthAddress, uint256 pqNonce) = parseBasePQChangeETHAddressConfirmMessage(basePQMessage);
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. PQ signature address (recoveredFingerprint) must be currently registered
        address currentETHAddress = epervierKeyToAddress[recoveredFingerprint];
        require(currentETHAddress != address(0), "PQ fingerprint not registered");
        
        // 2. ETH message must be signed by the ETH address referenced by the PQ signature (current registered address)
        require(currentETHAddress == recoveredETHAddress, "ETH signature must be from current registered address");
        
        // 3. Old ETH address from PQ message must match the current registration
        require(oldEthAddress == currentETHAddress, "Old ETH address mismatch: PQ message vs current registration");
        
        // 4. ETH message must reference the PQ address (recoveredFingerprint)
        // Parse the BaseETHChangeETHAddressIntentMessage to extract the pqFingerprint
        (address ethMessagePqFingerprint, address ethMessageNewEthAddress, uint256 ethMessageNonce) = parseBaseETHChangeETHAddressIntentMessage(basePQMessage);
        require(ethMessagePqFingerprint == recoveredFingerprint, "ETH message PQ fingerprint mismatch");
        require(ethMessageNewEthAddress == newEthAddress, "ETH message new ETH address mismatch");
        
        
        // 5. PQ fingerprint must be currently registered to the old ETH address
        require(addressToEpervierKey[currentETHAddress] == recoveredFingerprint, "PQ key not registered to current address");
        
        // 6. Verify the new ETH address is different from the current one
        require(newEthAddress != currentETHAddress, "New ETH address must be different from current address");
        
        // 7. Check if the new ETH address already has a registered PQ key
        require(addressToEpervierKey[newEthAddress] == address(0), "New ETH address already has registered PQ key");
        
        // 8. Conflict prevention: Check for other pending intents
        // Check for pending registration intents
        require(pendingIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(pendingIntents[newEthAddress].timestamp == 0, "New ETH address has pending registration intent");
        
        // Check for pending unregistration intents
        require(unregistrationIntents[currentETHAddress].timestamp == 0, "Current ETH address has pending unregistration intent");
        require(unregistrationIntents[newEthAddress].timestamp == 0, "New ETH address has pending unregistration intent");
        
        // Check for other pending change intents
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        
        // SIXTH: Verify ETH nonce
        require(ethNonces[currentETHAddress] == ethNonce, "ERR9: Invalid ETH nonce in submitChangeETHAddressIntent");
        
        // Store the change intent
        changeETHAddressIntents[recoveredFingerprint] = ChangeETHAddressIntent({
            newETHAddress: newEthAddress,
            pqMessage: basePQMessage,
            timestamp: block.timestamp,
            pqNonce: pqKeyNonces[recoveredFingerprint] // Use current PQ nonce
        });
        
        // Increment ETH nonce
        ethNonces[currentETHAddress]++;

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
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = parseETHChangeETHAddressConfirmationMessage(ethMessage);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // FOURTH: Parse the base PQ change address confirmation message using our standardized schema
        (address oldEthAddress, address newEthAddress, uint256 pqNonce) = parseBasePQChangeETHAddressConfirmMessage(basePQMessage);
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. New ETH address from PQ message must match recovered ETH address from ETH signature
        require(newEthAddress == recoveredETHAddress, "ETH address mismatch: PQ message vs recovered ETH signature");
        
        // 2. Check that there's a pending change intent for this PQ fingerprint
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        
        // 3. New ETH address from PQ message must match the stored intent new ETH address
        require(intent.newETHAddress == newEthAddress, "ETH address mismatch: PQ message vs stored intent");
        
        // 4. Old ETH address from PQ message must match the current registration
        require(addressToEpervierKey[oldEthAddress] == recoveredFingerprint, "Old ETH address mismatch: PQ message vs current registration");
        
        // 5. PQ fingerprint must be currently registered to the old ETH address
        require(epervierKeyToAddress[recoveredFingerprint] == oldEthAddress, "PQ fingerprint not registered to old ETH address");
        
        // 6. Verify intent message consistency
        require(keccak256(intent.pqMessage) == keccak256(basePQMessage), "Intent message mismatch");
        
        // SIXTH: Verify ETH nonce
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "ERR4: Invalid PQ nonce in submitRegistrationIntent");
        require(ethNonces[newEthAddress] == ethNonce, "ERR6: Invalid ETH nonce in confirmChangeETHAddress");
        
        // SEVENTH: Complete the change
        epervierKeyToAddress[recoveredFingerprint] = newEthAddress;
        addressToEpervierKey[oldEthAddress] = address(0); // Clear old mapping
        addressToEpervierKey[newEthAddress] = recoveredFingerprint; // Set new mapping
        
        // Clear the intent
        delete changeETHAddressIntents[recoveredFingerprint];
        
        emit ChangeETHAddressConfirmed(recoveredFingerprint, oldEthAddress, newEthAddress);
    }
    
    function removeChangeETHAddressIntent(
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
        
        // SECOND: Parse the current ETH address from the PQ message
        address currentETHAddress = parseCurrentETHAddress(pqMessage);
        require(currentETHAddress != address(0), "Invalid current ETH address");
        
        // THIRD: Derive public key address from the recovered address
        address publicKeyAddress = recoveredFingerprint;
        
        // FOURTH: Verify that the PQ key is currently registered to the current ETH address
        require(addressToEpervierKey[publicKeyAddress] == currentETHAddress, "PQ key not registered to current address");
        
        // FIFTH: Extract PQ nonce from the PQ message
        uint256 pqNonce = extractPQNonce(pqMessage, 0);
        
        // SIXTH: Check if there's a pending change intent
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[publicKeyAddress];
        require(intent.timestamp != 0, "No pending change intent found");
        
        // SEVENTH: Verify PQ nonce
        require(pqKeyNonces[publicKeyAddress] == pqNonce, "Invalid PQ nonce");
        
        // EIGHTH: Verify the PQ message contains the correct removal text
        require(validatePQRemovalMessage(pqMessage), "Invalid PQ removal message");
        
        // Clear the intent
        delete changeETHAddressIntents[publicKeyAddress];
        
        // Increment PQ nonce
        pqKeyNonces[publicKeyAddress]++;

        emit ChangeETHAddressIntentRemoved(publicKeyAddress);
    }
    
    /**
     * @dev Submit unregistration intent with nested signatures
     * @param pqMessage The PQ message signed by Epervier (contains ETH address, nonce, and signature)
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
        // FIRST: Verify the PQ signature and recover the ETH address
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress != address(0), "Invalid intent address");
        
        // THIRD: Extract ETH nonce from the PQ message
        uint256 ethNonce = extractEthNonce(pqMessage, 0);
        
        // FOURTH: Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "ERR10: Invalid ETH nonce in submitUnregistrationIntent");
        
        // FIFTH: Verify PQ nonce from message
        uint256 pqNonce = extractPQNonce(pqMessage, 0);
        require(pqNonce == 0, "PQ nonce must be 0 for unregistration intent");
        
        // SIXTH: Check if this address has a registered key
        address publicKeyAddress = recoveredAddress;
        require(addressToEpervierKey[intentAddress] == publicKeyAddress, "Address has no registered Epervier key");
        
        // SEVENTH: Conflict prevention: Check for other pending intents
        // Check for pending registration intents
        require(pendingIntents[intentAddress].timestamp == 0, "ETH address has pending registration intent");
        require(pendingIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending registration intent");
        
        // Check for pending change intents
        require(changeETHAddressIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending change intent");
        
        // Check for pending unregistration intents
        require(unregistrationIntents[intentAddress].timestamp == 0, "ETH address has pending unregistration intent");
        
        // EIGHTH: Extract ETH signature from the PQ message
        bytes memory ethSignature = extractETHSignature(pqMessage);
        require(ethSignature.length == 65, "Invalid ETH signature length");
        
        // NINTH: Parse ETH signature components
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        // Extract r (first 32 bytes)
        for (uint i = 0; i < 32; i++) {
            r = bytes32(uint256(r) | (uint256(uint8(ethSignature[i])) << (8 * (31 - i))));
        }
        
        // Extract s (next 32 bytes)
        for (uint i = 0; i < 32; i++) {
            s = bytes32(uint256(s) | (uint256(uint8(ethSignature[32 + i])) << (8 * (31 - i))));
        }
        
        // Extract v (last byte)
        v = uint8(ethSignature[64]);
        
        // NINTH: Create the ETH message that includes the PQ message
        bytes memory ethMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to unregister from PQ fingerprint",
            ethNonce,
            pqMessage // Include the PQ message that was signed
        );
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        // TENTH: Verify the ETH signature
        address ethSigner = ECDSA.recover(ethSignedMessageHash, v, r, s);
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
        bytes memory salt = extractPQSalt(ethMessage, 2);
        uint256[] memory cs1 = extractPQCs1(ethMessage, 2);
        uint256[] memory cs2 = extractPQCs2(ethMessage, 2);
        uint256 hint = extractPQHint(ethMessage, 2);
        bytes memory basePQMessage = extractBasePQMessage(ethMessage, 2);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // FOURTH: Parse the ETH address from the base PQ message
        address intentAddress = parseIntentAddress(basePQMessage);
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");
        
        // FIFTH: Comprehensive cross-reference validation
        // 1. ETH address from PQ message must match recovered ETH address from ETH signature
        require(intentAddress == recoveredETHAddress, "ETH address mismatch: PQ message vs recovered ETH signature");
        
        // 2. Check that there's a pending unregistration intent for this ETH address
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found for ETH address");
        
        // 3. PQ fingerprint from ETH message must match recovered PQ fingerprint from PQ signature
        require(intent.publicKeyAddress == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // 4. ETH address must be currently registered to the PQ fingerprint
        require(addressToEpervierKey[intentAddress] == recoveredFingerprint, "ETH address not registered to PQ fingerprint");
        
        // 5. PQ fingerprint must be currently registered to the ETH address
        require(epervierKeyToAddress[recoveredFingerprint] == intentAddress, "PQ fingerprint not registered to ETH address");
        
        // 6. Verify intent message consistency
        require(keccak256(intent.pqMessage) == keccak256(basePQMessage), "Intent message mismatch");
        
        // SIXTH: Extract ETH nonce from the base PQ message
        uint256 ethNonce = extractEthNonce(basePQMessage, 1); // 1 for confirmation message
        
        // SEVENTH: Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "ERR11: Invalid ETH nonce in confirmUnregistration");
        
        // EIGHTH: Verify PQ nonce from message
        uint256 pqNonce = extractPQNonce(basePQMessage, 0);
        require(pqNonce == 0, "PQ nonce must be 0 for unregistration confirmation");
        
        // NINTH: Derive public key address from the recovered address
        address publicKeyAddress = recoveredFingerprint;
        
        // TENTH: Verify the public key matches the intent
        require(intent.publicKeyAddress == publicKeyAddress, "Public key mismatch");
        
        // ELEVENTH: Verify intent message consistency
        require(keccak256(intent.pqMessage) == keccak256(basePQMessage), "Intent message mismatch");
        
        // TWELFTH: Verify the ETH message contains the correct confirmation text
        require(validateETHUnregistrationConfirmationMessage(ethMessage), "Invalid ETH confirmation message");
        
        // THIRTEENTH: Verify the PQ message contains the correct confirmation text
        require(validatePQUnregistrationConfirmationMessage(basePQMessage), "Invalid PQ confirmation message");
        
        // Remove the mappings
        epervierKeyToAddress[publicKeyAddress] = address(0);
        addressToEpervierKey[intentAddress] = address(0);
        
        // Clear the intent
        delete unregistrationIntents[intentAddress];
        
        // Increment nonces
        ethNonces[intentAddress]++;
        pqKeyNonces[publicKeyAddress]++;

        emit UnregistrationConfirmed(intentAddress, publicKeyAddress);
    }
    
    /**
     * @dev Remove a pending unregistration intent
     * @param pqMessage The message signed by the PQ key (contains ETH address and nonce)
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
        // FIRST: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        // Note: We don't validate the signature here because Epervier recover() always returns an address
        // The signature will be validated by comparing fingerprints
        
        // SECOND: Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress != address(0), "Invalid intent address");
        
        // THIRD: Derive public key address from the recovered address
        address publicKeyAddress = recoveredFingerprint;
        
        // FOURTH: Check if there's a pending unregistration intent
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        
        // FIFTH: Verify the public key address matches the intent
        require(intent.publicKeyAddress == publicKeyAddress, "PQ key mismatch");
        
        // SIXTH: Verify the PQ message contains the correct removal text
        require(validatePQUnregistrationRemovalMessage(pqMessage), "Invalid PQ removal message");
        
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
     * @dev Parse ETH address from PQ remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function parseRemoveIntentAddress(bytes memory message) internal pure returns (address intentAddress) {
        // Look for the pattern "Remove intent from address " followed by an address
        bytes memory pattern = "Remove intent from address ";
        
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
        require(message.length >= 32 + 26 + 20 + 32, "Message too short for PQ nonce from remove message");
        
        // Extract the PQ nonce (last 32 bytes of the message)
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[message.length - 32 + j];
        }
        return abi.decode(nonceBytes, (uint256));
    }
    
    /**
     * @dev Validate that PQ message contains removal text for registration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function validatePQRemoveIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove intent from address ";
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
        
        // SECOND: Use the bidirectional mapping to find the ETH address with pending intent
        address intentAddress = pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        require(intentAddress != address(0), "No pending intent found for this PQ fingerprint");
        
        // THIRD: Comprehensive cross-reference validation
        // 1. Check if there's a pending intent for the referenced ETH address
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for referenced ETH address");
        
        // 2. Verify the recovered PQ fingerprint matches the stored intent
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        
        // 3. Verify the bidirectional mapping is consistent
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] == intentAddress, "Bidirectional mapping mismatch");
        
        // FOURTH: Extract PQ nonce from the PQ message
        uint256 pqNonce = extractPQNonceFromRemoveMessage(pqMessage);
        
        // FIFTH: Verify PQ nonce
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // SIXTH: Verify the PQ message contains the correct removal text
        require(validatePQRemoveIntentMessage(pqMessage), "Invalid PQ removal message");
        
        // Clear both mappings
        delete pendingIntents[intentAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // Increment PQ nonce
        pqKeyNonces[recoveredFingerprint]++;
        
        emit RegistrationIntentRemoved(intentAddress);
    }

    /**
     * @dev Parse ETH address from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
     */
    function parseETHAddressFromConfirmMessage(bytes memory message) internal pure returns (address ethAddress) {
        // Check if message is long enough to contain the pattern + ethAddress
        require(message.length >= 32 + 35 + 20, "Message too short for ETH address from confirm message");
        
        // Extract the ETH address (20 bytes after DOMAIN_SEPARATOR + "Confirm binding ETH Address ")
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
    ) internal pure returns (bytes[] memory parsedFields) {
        require(fieldOffsets.length == fieldLengths.length, "Field offsets and lengths must match");
        require(fieldOffsets.length == fieldTypes.length, "Field offsets and types must match");
        
        // Verify the pattern exists in the message
        uint256 patternIndex = findPattern(message, expectedPattern);
        require(patternIndex != type(uint256).max, "Expected pattern not found in message");
        
        parsedFields = new bytes[](fieldOffsets.length);
        
        for (uint256 i = 0; i < fieldOffsets.length; i++) {
            uint256 fieldStart = fieldOffsets[i];
            uint256 fieldLength = fieldLengths[i];
            
            require(fieldStart + fieldLength <= message.length, "Field extends beyond message length");
            
            parsedFields[i] = new bytes(fieldLength);
            for (uint256 j = 0; j < fieldLength; j++) {
                parsedFields[i][j] = message[fieldStart + j];
            }
        }
        
        return parsedFields;
    }
    
    /**
     * @dev Parse a BasePQRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce
     */
    function parseBasePQRegistrationIntentMessage(bytes memory message) public pure returns (
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
    function parseETHRegistrationIntentMessage(bytes memory message) internal pure returns (
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
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to epervier fingerprint " + pqFingerprint + ethNonce
     */
    function parseBaseETHRegistrationConfirmationMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Confirm bonding to epervier fingerprint ";
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
    function parsePQRegistrationConfirmationMessage(bytes memory message) public pure returns (
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
    function parseETHRemoveIntentMessage(bytes memory message) internal pure returns (
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
    function parsePQRemoveIntentMessage(bytes memory message) internal pure returns (
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
     * Expected format: DOMAIN_SEPARATOR + "Intent to Change ETH Address for fingeprint " + pqFingerprint + " to " + newEthAddress + ethNonce
     */
    function parseBaseETHChangeETHAddressIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        address newEthAddress,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to Change ETH Address for fingeprint ";
        uint256[] memory fieldOffsets = new uint256[](4);
        uint256[] memory fieldLengths = new uint256[](4);
        string[] memory fieldTypes = new string[](4);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (44) = 76
        fieldOffsets[0] = 76;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after pqFingerprint = 76 + 20 = 96, length = 4
        fieldOffsets[1] = 96;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 96 + 4 = 100, length = 20
        fieldOffsets[2] = 100;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // ethNonce: starts after newEthAddress = 100 + 20 = 120, length = 32
        fieldOffsets[3] = 120;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 44, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * Expected format: DOMAIN_SEPARATOR + "Change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQChangeETHAddressIntentMessage(bytes memory message) internal pure returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 ethNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        bytes memory pattern = "Change bound ETH Address from ";
        uint256[] memory fieldOffsets = new uint256[](8);
        uint256[] memory fieldLengths = new uint256[](8);
        string[] memory fieldTypes = new string[](8);
        
        // oldEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (29) = 61
        fieldOffsets[0] = 61;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 61 + 20 = 81, length = 4
        fieldOffsets[1] = 81;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 81 + 4 = 85, length = 20
        fieldOffsets[2] = 85;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // baseETHMessage: starts after newEthAddress = 85 + 20 = 105, length = 152
        fieldOffsets[3] = 105;
        fieldLengths[3] = 152;
        fieldTypes[3] = "bytes";
        
        // v: starts after baseETHMessage = 105 + 152 = 257, length = 1
        fieldOffsets[4] = 257;
        fieldLengths[4] = 1;
        fieldTypes[4] = "uint8";
        
        // r: starts after v = 257 + 1 = 258, length = 32
        fieldOffsets[5] = 258;
        fieldLengths[5] = 32;
        fieldTypes[5] = "bytes32";
        
        // s: starts after r = 258 + 32 = 290, length = 32
        fieldOffsets[6] = 290;
        fieldLengths[6] = 32;
        fieldTypes[6] = "bytes32";
        
        // pqNonce: starts after s = 290 + 32 = 322, length = 32
        fieldOffsets[7] = 322;
        fieldLengths[7] = 32;
        fieldTypes[7] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 29, fieldOffsets, fieldLengths, fieldTypes);
        
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
        ethNonce = uint256(bytes32(parsedFields[7]));
    }
    
    /**
     * @dev Parse a BasePQChangeETHAddressConfirmMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing ETH address from " + oldEthAddress + " to " + newEthAddress + pqNonce
     */
    function parseBasePQChangeETHAddressConfirmMessage(bytes memory message) internal pure returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm changing ETH address from ";
        uint256[] memory fieldOffsets = new uint256[](4);
        uint256[] memory fieldLengths = new uint256[](4);
        string[] memory fieldTypes = new string[](4);
        
        // oldEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (32) = 64
        fieldOffsets[0] = 64;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 64 + 20 = 84, length = 4
        fieldOffsets[1] = 84;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 84 + 4 = 88, length = 20
        fieldOffsets[2] = 88;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // pqNonce: starts after newEthAddress = 88 + 20 = 108, length = 32
        fieldOffsets[3] = 108;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 32, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * @dev Parse an ETHChangeETHAddressConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address and bond with fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHChangeETHAddressConfirmationMessage(bytes memory message) internal pure returns (
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Confirm change ETH Address and bond with fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (47) = 79, length = 20
        fieldOffsets[0] = 79;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 79 + 20 = 99, length = 140
        fieldOffsets[1] = 99;
        fieldLengths[1] = 140;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 99 + 140 = 239, length = 40
        fieldOffsets[2] = 239;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 239 + 40 = 279, length = 32 * 32 = 1024
        fieldOffsets[3] = 279;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 279 + 1024 = 1303, length = 32 * 32 = 1024
        fieldOffsets[4] = 1303;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1303 + 1024 = 2327, length = 32
        fieldOffsets[5] = 2327;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2327 + 32 = 2359, length = 32
        fieldOffsets[6] = 2359;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * @dev Parse a BaseETHUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from PQ fingerprint" + pqFingerprint + ethNonce
     */
    function parseBaseETHUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to unregister from PQ fingerprint";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59
        fieldOffsets[0] = 59;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 59 + 20 = 79
        fieldOffsets[1] = 79;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from PQ fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address currentEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        bytes memory pattern = "Intent to unregister from PQ fingerprint from address ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // currentEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (59) = 91
        fieldOffsets[0] = 91;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // baseETHMessage: starts after currentEthAddress = 91 + 20 = 111, length = 111
        fieldOffsets[1] = 111;
        fieldLengths[1] = 111;
        fieldTypes[1] = "bytes";
        
        // v: starts after baseETHMessage = 111 + 111 = 222, length = 1
        fieldOffsets[2] = 222;
        fieldLengths[2] = 1;
        fieldTypes[2] = "uint8";
        
        // r: starts after v = 222 + 1 = 223, length = 32
        fieldOffsets[3] = 223;
        fieldLengths[3] = 32;
        fieldTypes[3] = "bytes32";
        
        // s: starts after r = 223 + 32 = 255, length = 32
        fieldOffsets[4] = 255;
        fieldLengths[4] = 32;
        fieldTypes[4] = "bytes32";
        
        // pqNonce: starts after s = 255 + 32 = 287, length = 32
        fieldOffsets[5] = 287;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 59, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        currentEthAddress = address(uint160(addr));
        baseETHMessage = parsedFields[1];
        v = uint8(parsedFields[2][0]);
        r = bytes32(parsedFields[3]);
        s = bytes32(parsedFields[4]);
        pqNonce = uint256(bytes32(parsedFields[5]));
    }
    
    /**
     * @dev Parse a BasePQUnregistrationConfirmMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address" + ethAddress + pqNonce
     */
    function parseBasePQUnregistrationConfirmMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm unregistration from ETH Address";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (35) = 67
        fieldOffsets[0] = 67;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 67 + 20 = 87
        fieldOffsets[1] = 87;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 35, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse an ETHUnregistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from PQ fingerprint" + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Confirm unregistration from PQ fingerprint";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59
        fieldOffsets[0] = 59;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 59 + 20 = 79, length = 111
        fieldOffsets[1] = 79;
        fieldLengths[1] = 111;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 79 + 111 = 190, length = 40
        fieldOffsets[2] = 190;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 190 + 40 = 230, length = 32 * 32 = 1024
        fieldOffsets[3] = 230;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 230 + 1024 = 1254, length = 32 * 32 = 1024
        fieldOffsets[4] = 1254;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1254 + 1024 = 2278, length = 32
        fieldOffsets[5] = 2278;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2278 + 32 = 2310, length = 32
        fieldOffsets[6] = 2310;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from address" + pqFingerprint + ethNonce
     */
    function parseETHRemoveRegistrationIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove registration intent from address";
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
     * @dev Parse an ETHRemoveChangeIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from address" + pqFingerprint + ethNonce
     */
    function parseETHRemoveChangeIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove change intent from address";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (30) = 62
        fieldOffsets[0] = 62;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 62 + 20 = 82
        fieldOffsets[1] = 82;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 30, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse an ETHRemoveUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from address" + pqFingerprint + ethNonce
     */
    function parseETHRemoveUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove unregistration intent from address";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (34) = 66
        fieldOffsets[0] = 66;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 66 + 20 = 86
        fieldOffsets[1] = 86;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 34, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from address " + ethAddress + pqNonce
     */
    function parsePQRemoveRegistrationIntentMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove registration intent from address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (36) = 68
        fieldOffsets[0] = 68;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 68 + 20 = 88
        fieldOffsets[1] = 88;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 36, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveChangeIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from address " + ethAddress + pqNonce
     */
    function parsePQRemoveChangeIntentMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove change intent from address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (31) = 63
        fieldOffsets[0] = 63;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 63 + 20 = 83
        fieldOffsets[1] = 83;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 31, fieldOffsets, fieldLengths, fieldTypes);
        
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
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from address " + ethAddress + pqNonce
     */
    function parsePQRemoveUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove unregistration intent from address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (35) = 67
        fieldOffsets[0] = 67;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 67 + 20 = 87
        fieldOffsets[1] = 87;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 35, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
} 
