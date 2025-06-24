// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

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
        uint256[2] publicKey;
        bytes intentMessage;
        uint256 timestamp;
        uint256 ethNonce;
    }
    mapping(address => Intent) public pendingIntents;
    
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
        uint256 ethNonce;
    }
    
    mapping(address => UnregistrationIntent) public unregistrationIntents;
    
    event EpervierKeyDeleted(address indexed owner, address indexed publicKeyAddress);
    event PQSecurityDisabled(address indexed owner);
    event PQSecurityEnabled(address indexed owner, address indexed publicKeyAddress);
    event RegistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint, uint256 ethNonce);
    event RegistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationIntentRemoved(address indexed ethAddress);
    event IntentRemoved(address indexed owner);
    event ChangeETHAddressIntentSubmitted(address indexed pqFingerprint, address indexed newETHAddress, uint256 pqNonce);
    event ChangeETHAddressConfirmed(address indexed pqFingerprint, address indexed oldETHAddress, address indexed newETHAddress);
    event ChangeETHAddressIntentRemoved(address indexed pqFingerprint);
    event UnregistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint, uint256 ethNonce);
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
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractPQSalt(bytes memory message) internal pure returns (bytes memory salt) {
        // Check if message is long enough to contain the pattern + ethNonce + salt
        require(message.length >= 32 + 27 + 32 + 40, "Message too short for PQ salt");
        
        // Extract the salt (40 bytes after DOMAIN_SEPARATOR + pattern + ethNonce)
        bytes memory saltBytes = new bytes(40);
        for (uint j = 0; j < 40; j++) {
            saltBytes[j] = message[32 + 27 + 32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + offset
        }
        return saltBytes;
    }

    /**
     * @dev Extract PQ signature cs1 from ETH message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractPQCs1(bytes memory message) internal pure returns (uint256[] memory cs1) {
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1
        require(message.length >= 32 + 27 + 32 + 40 + 32*32, "Message too short for PQ cs1");
        
        // Extract cs1 (32 uint256 values after salt)
        cs1 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs1Bytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs1Bytes[j] = message[32 + 27 + 32 + 40 + i*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + offset
            }
            cs1[i] = abi.decode(cs1Bytes, (uint256));
        }
        return cs1;
    }

    /**
     * @dev Extract PQ signature cs2 from ETH message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractPQCs2(bytes memory message) internal pure returns (uint256[] memory cs2) {
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2
        require(message.length >= 32 + 27 + 32 + 40 + 32*32 + 32*32, "Message too short for PQ cs2");
        
        // Extract cs2 (32 uint256 values after cs1)
        cs2 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs2Bytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs2Bytes[j] = message[32 + 27 + 32 + 40 + 32*32 + i*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + offset
            }
            cs2[i] = abi.decode(cs2Bytes, (uint256));
        }
        return cs2;
    }

    /**
     * @dev Extract PQ signature hint from ETH message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractPQHint(bytes memory message) internal pure returns (uint256 hint) {
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2 + hint
        require(message.length >= 32 + 27 + 32 + 40 + 32*32 + 32*32 + 32, "Message too short for PQ hint");
        
        // Extract hint (32 bytes after cs2)
        bytes memory hintBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            hintBytes[j] = message[32 + 27 + 32 + 40 + 32*32 + 32*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + cs2 + offset
        }
        hint = abi.decode(hintBytes, (uint256));
        
        // Debug logging (note: this won't work in pure functions, but we can add it to the calling function)
        return hint;
    }

    /**
     * @dev Extract base PQ message from ETH message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractBasePQMessage(bytes memory message) internal pure returns (bytes memory basePQMessage) {
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2 + hint
        require(message.length >= 32 + 27 + 32 + 40 + 32*32 + 32*32 + 32, "Message too short for base PQ message");
        
        // Extract base PQ message (everything after hint)
        uint256 baseMessageStart = 32 + 27 + 32 + 40 + 32*32 + 32*32 + 32; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + cs2 + hint
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
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
     */
    function extractETHMessageFromPQMessage(bytes memory message) internal pure returns (bytes memory ethMessage) {
        // Check if message is long enough to contain the pattern + address + pqNonce + ethSignature
        require(message.length >= 32 + 27 + 20 + 32 + 65, "Message too short for ETH message");
        
        // Extract the ETH message (everything after the ETH signature)
        uint256 ethMessageStart = 32 + 27 + 20 + 32 + 65; // DOMAIN_SEPARATOR + pattern + address + pqNonce + ethSignature
        uint256 ethMessageLength = message.length - ethMessageStart;
        
        ethMessage = new bytes(ethMessageLength);
        for (uint j = 0; j < ethMessageLength; j++) {
            ethMessage[j] = message[ethMessageStart + j];
        }
        return ethMessage;
    }

    /**
     * @dev Extract ETH signature from PQ confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
     */
    function extractETHSignatureFromPQMessage(bytes memory message) internal returns (bytes memory ethSignature) {
        // Check if message is long enough to contain the pattern + address + pqNonce + ethSignature
        require(message.length >= 32 + 27 + 20 + 32 + 65, "Message too short for ETH signature");
        
        // Extract the ETH signature (65 bytes after DOMAIN_SEPARATOR + pattern + address + pqNonce)
        // Position: 32 + 27 + 20 + 32 = 111 bytes from start
        uint256 signatureStart = 32 + 27 + 20 + 32; // DOMAIN_SEPARATOR + pattern + address + pqNonce
        bytes memory signatureBytes = new bytes(65);
        for (uint j = 0; j < 65; j++) {
            signatureBytes[j] = message[signatureStart + j];
        }
        // Debug: emit the extracted signature bytes as an event (first 10 bytes for brevity)
        bytes memory debugFirst10 = new bytes(10);
        for (uint j = 0; j < 10; j++) {
            debugFirst10[j] = signatureBytes[j];
        }
        emit DebugEthMessageHex(debugFirst10);
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
            fingerprintBytes[j] = message[32 + 40 + j]; // DOMAIN_SEPARATOR + pattern (40 bytes) + offset
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
     * Expected format: DOMAIN_SEPARATOR + "Change ETH Address from " + currentAddress + " to " + newAddress + pqNonce
     */
    function parseCurrentETHAddress(bytes memory message) internal pure returns (address currentAddress) {
        // Look for the pattern "Change ETH Address from " followed by an address
        bytes memory pattern = "Change ETH Address from ";
        
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
     * Expected format: DOMAIN_SEPARATOR + "Change ETH Address from " + currentAddress + " to " + newAddress + pqNonce
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
        
        // SECOND: Parse PQ signature components from the ETH message
        bytes memory salt = extractPQSalt(ethMessage);
        uint256[] memory cs1 = extractPQCs1(ethMessage);
        uint256[] memory cs2 = extractPQCs2(ethMessage);
        uint256 hint = extractPQHint(ethMessage);
        bytes memory basePQMessage = extractBasePQMessage(ethMessage);
        
        // Debug logging for extracted components
        emit DebugParseStep("extracted_hint", hint);
        emit DebugParseStep("salt_length", salt.length);
        emit DebugParseStep("cs1_length", cs1.length);
        emit DebugParseStep("cs2_length", cs2.length);
        emit DebugParseStep("base_pq_message_length", basePQMessage.length);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        emit DebugParseStep("pq_recovery_result", uint256(uint160(recoveredFingerprint)));
        require(recoveredFingerprint != address(0), "ERR2: Invalid Epervier signature");
        
        // FOURTH: Parse the ETH address from the base PQ message
        address intentAddress = parseIntentAddress(basePQMessage);
        emit DebugParseStep("recovered_eth_address", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address", uint256(uint160(intentAddress)));
        emit DebugParseStep("extracted_eth_nonce", extractEthNonce(ethMessage, 0));
        emit DebugParseStep("current_eth_nonce", ethNonces[intentAddress]);
        
        // Debug: Log the address comparison
        emit DebugParseStep("recovered_eth_address_uint", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address_uint", uint256(uint160(intentAddress)));
        emit DebugParseStep("addresses_equal", uint256(uint160(recoveredETHAddress == intentAddress ? 1 : 0)));
        require(intentAddress == recoveredETHAddress, "ERR3: ETH signature must be from intent address");
        
        // FIFTH: Extract ETH nonce from the ETH message
        uint256 ethNonce = extractEthNonce(ethMessage, 0); // 0 for intent message
        
        // Debug: Log the extracted nonce
        emit DebugParseStep("confirm_eth_nonce_extracted", ethNonce);
        emit DebugParseStep("confirm_eth_nonce_expected", ethNonces[intentAddress]);
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "ERR6: Invalid ETH nonce in submitRegistrationIntent");
        
        // Check if Epervier key is already registered
        require(addressToEpervierKey[intentAddress] == address(0), "ERR5: Epervier key already registered");
        
        // Store the intent with the recovered fingerprint address directly
        pendingIntents[intentAddress] = Intent({
            pqFingerprint: recoveredFingerprint,  // Use recovered address directly
            publicKey: [uint256(0), uint256(0)], // Placeholder - not needed for storage
            intentMessage: basePQMessage,
            timestamp: block.timestamp,
            ethNonce: ethNonce
        });
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        // Increment PQ nonce to prevent replay attacks
        pqKeyNonces[recoveredFingerprint]++;  // Use recovered address directly
        
        emit RegistrationIntentSubmitted(intentAddress, recoveredFingerprint, ethNonce);
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
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");

        // SECOND: Parse the ETH message and signature from the PQ message
        // Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
        bytes memory ethMessage = extractETHMessageFromPQMessage(pqMessage);
        bytes memory ethSignature = extractETHSignatureFromPQMessage(pqMessage);
        
        // Add debug logging to see the PQ message structure
        emit DebugParseStep("pq_message_total_length", pqMessage.length);
        emit DebugParseStep("expected_eth_message_start", 32 + 27 + 20 + 32 + 65); // DOMAIN_SEPARATOR + pattern + address + pqNonce + ethSignature
        
        // Add after extracting ethMessage and ethSignature
        emit DebugParseStep("extracted_eth_message_length", ethMessage.length);
        emit DebugParseStep("extracted_eth_signature_length", ethSignature.length);
        emit DebugParseStep("pq_message_length", pqMessage.length);
        
        // Debug: Print the length and first 64 bytes of the ETH message
        emit DebugParseStep("eth_message_length", ethMessage.length);
        // Debug: Print the first 64 bytes of the ETH message
        for (uint i = 0; i < 64 && i < ethMessage.length; i++) {
            emit DebugParseStep("eth_message_byte", uint8(ethMessage[i]));
        }
        
        // Parse ETH signature components
        require(ethSignature.length == 65, "Invalid ETH signature length");
        
        emit DebugParseStep("about_to_parse_signature", 0);
        emit DebugParseStep("eth_signature_bytes_0", uint256(uint8(ethSignature[0])));
        emit DebugParseStep("eth_signature_bytes_32", uint256(uint8(ethSignature[32])));
        emit DebugParseStep("eth_signature_bytes_64", uint256(uint8(ethSignature[64])));
        
        // Add more debug logging to see the actual signature bytes
        emit DebugParseStep("eth_signature_bytes_1", uint256(uint8(ethSignature[1])));
        emit DebugParseStep("eth_signature_bytes_2", uint256(uint8(ethSignature[2])));
        emit DebugParseStep("eth_signature_bytes_3", uint256(uint8(ethSignature[3])));
        emit DebugParseStep("eth_signature_bytes_30", uint256(uint8(ethSignature[30])));
        emit DebugParseStep("eth_signature_bytes_31", uint256(uint8(ethSignature[31])));
        emit DebugParseStep("eth_signature_bytes_33", uint256(uint8(ethSignature[33])));
        emit DebugParseStep("eth_signature_bytes_34", uint256(uint8(ethSignature[34])));
        emit DebugParseStep("eth_signature_bytes_62", uint256(uint8(ethSignature[62])));
        emit DebugParseStep("eth_signature_bytes_63", uint256(uint8(ethSignature[63])));
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(ethSignature, 32))
            s := mload(add(ethSignature, 64))
            v := byte(0, mload(add(ethSignature, 96)))
        }
        
        emit DebugParseStep("parsed_eth_signature_v", v);
        emit DebugParseStep("parsed_eth_signature_r", uint256(r));
        emit DebugParseStep("parsed_eth_signature_s", uint256(s));
        
        // THIRD: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        emit DebugParseStep("confirm_eth_message_length", ethMessage.length);
        emit DebugParseStep("confirm_eth_message_hash", uint256(ethMessageHash));
        emit DebugParseStep("confirm_eth_signed_message_hash", uint256(ethSignedMessageHash));
        emit DebugParseStep("confirm_eth_signature_v", v);
        emit DebugParseStep("confirm_eth_signature_r", uint256(r));
        emit DebugParseStep("confirm_eth_signature_s", uint256(s));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        emit DebugParseStep("confirm_eth_recovered_address", uint256(uint160(recoveredETHAddress)));
        require(recoveredETHAddress != address(0), "Invalid ETH signature");

        // FOURTH: Parse the intent address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress != address(0), "Invalid intent address");
        emit DebugParseStep("confirm_intent_address", uint256(uint160(intentAddress)));
        emit DebugParseStep("recovered_eth_address_uint", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address_uint", uint256(uint160(intentAddress)));
        emit DebugParseStep("addresses_equal", uint256(uint160(recoveredETHAddress == intentAddress ? 1 : 0)));
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");

        // FIFTH: Extract ETH nonce from the ETH message
        uint256 ethNonce = extractEthNonce(ethMessage, 1); // 1 for confirmation message
        
        // Debug: Log the extracted nonce and verify the message structure
        emit DebugParseStep("confirm_eth_nonce_extracted", ethNonce);
        emit DebugParseStep("confirm_eth_nonce_expected", ethNonces[intentAddress]);
        
        // Debug: Let's manually extract the nonce to see what's happening
        emit DebugParseStep("eth_message_length_for_nonce", ethMessage.length);
        emit DebugParseStep("expected_nonce_position", 32 + 35 + 32);
        
        // Manually extract the nonce bytes to debug
        if (ethMessage.length >= 32 + 35 + 32 + 32) {
            bytes memory manualNonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                manualNonceBytes[j] = ethMessage[32 + 35 + 32 + j];
            }
            // Convert to uint256 manually
            uint256 manualNonce = 0;
            for (uint j = 0; j < 32; j++) {
                manualNonce = (manualNonce << 8) | uint8(manualNonceBytes[j]);
            }
            emit DebugParseStep("manual_nonce_extracted", manualNonce);
            
            // Debug: Print the first few bytes of the nonce
            emit DebugParseStep("nonce_byte_0", uint8(manualNonceBytes[0]));
            emit DebugParseStep("nonce_byte_1", uint8(manualNonceBytes[1]));
            emit DebugParseStep("nonce_byte_30", uint8(manualNonceBytes[30]));
            emit DebugParseStep("nonce_byte_31", uint8(manualNonceBytes[31]));
        }
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "ERR6: Invalid ETH nonce in confirmRegistration");

        // Verify PQ message format and extract PQ nonce
        uint256 pqNonce = extractPQNonce(pqMessage, 1); // 1 for confirmation message format
        require(pqNonce == pqKeyNonces[recoveredFingerprint], "PQ nonce mismatch");

        // SIXTH: Verify the intent message matches the base PQ message from the current pqMessage
        bytes memory basePQMessageFromConfirm = extractBasePQMessageFromPQMessage(pqMessage);
        require(keccak256(pendingIntents[intentAddress].intentMessage) == keccak256(basePQMessageFromConfirm), "Intent message mismatch");

        // SEVENTH: Verify the intent fingerprint matches the recovered fingerprint
        address ethMessageFingerprint = extractFingerprintFromETHMessage(ethMessage);
        
        // Debug: Log the fingerprint values being compared
        emit DebugParseStep("eth_message_fingerprint_uint", uint256(uint160(ethMessageFingerprint)));
        emit DebugParseStep("recovered_fingerprint_uint", uint256(uint160(recoveredFingerprint)));
        emit DebugParseStep("addresses_equal", uint256(uint160(ethMessageFingerprint == recoveredFingerprint ? 1 : 0)));
        
        require(
            ethMessageFingerprint == recoveredFingerprint,
            "ETH message fingerprint mismatch"
        );

        // Complete the registration
        epervierKeyToAddress[recoveredFingerprint] = intentAddress;
        addressToEpervierKey[intentAddress] = recoveredFingerprint;
        
        // Clear the pending intent
        delete pendingIntents[intentAddress];
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;

        emit RegistrationConfirmed(intentAddress, recoveredFingerprint);
    }
    
    /**
     * @dev Extract ETH nonce from remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent" + ethNonce + fingerprint
     */
    function extractEthNonceFromRemoveMessage(bytes memory message) internal pure returns (uint256 ethNonce) {
        require(message.length >= 32 + 26 + 32, "Message too short for ETH nonce from remove message");
        
        // Extract the ETH nonce (32 bytes after DOMAIN_SEPARATOR + "Remove registration intent")
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[32 + 26 + j]; // DOMAIN_SEPARATOR + "Remove registration intent" + offset
        }
        return abi.decode(nonceBytes, (uint256));
    }

    /**
     * @dev Extract fingerprint from remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent" + ethNonce + fingerprint
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
        
        // SECOND: Extract ETH nonce from the ETH message
        uint256 ethNonce = extractEthNonceFromRemoveMessage(ethMessage);
        
        // THIRD: Extract fingerprint from the ETH message
        address fingerprint = extractFingerprintFromRemoveMessage(ethMessage);
        
        // FOURTH: Check if there's a pending intent for this address
        Intent storage intent = pendingIntents[recoveredETHAddress];
        require(intent.timestamp != 0, "No pending intent found");
        
        // FIFTH: Verify the fingerprint matches the stored intent
        require(intent.pqFingerprint == fingerprint, "Fingerprint mismatch");
        
        // SIXTH: Verify ETH nonce
        require(ethNonces[recoveredETHAddress] == ethNonce, "ERR7: Invalid ETH nonce in removeIntent");
        
        // Clear the intent
        delete pendingIntents[recoveredETHAddress];
        
        // Increment ETH nonce
        ethNonces[recoveredETHAddress]++;
        
        emit RegistrationIntentRemoved(recoveredETHAddress);
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
        
        // SECOND: Parse PQ signature components from the ETH message
        bytes memory salt = extractPQSalt(ethMessage);
        uint256[] memory cs1 = extractPQCs1(ethMessage);
        uint256[] memory cs2 = extractPQCs2(ethMessage);
        uint256 hint = extractPQHint(ethMessage);
        bytes memory basePQMessage = extractBasePQMessage(ethMessage);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");
        
        // FOURTH: Parse the current ETH address from the base PQ message
        address currentETHAddress = parseCurrentETHAddress(basePQMessage);
        require(currentETHAddress != address(0), "Invalid current ETH address");
        
        // FIFTH: Verify that the ETH signature is from the current registered address
        require(currentETHAddress == recoveredETHAddress, "ETH signature must be from current registered address");
        
        // SIXTH: Parse the new ETH address from the base PQ message
        address intentNewAddress = parseNewETHAddress(basePQMessage);
        require(intentNewAddress != address(0), "Invalid new ETH address");
        
        // SEVENTH: Verify the new ETH address is different from the current one
        require(intentNewAddress != currentETHAddress, "New ETH address must be different from current address");
        
        // EIGHTH: Extract ETH nonce from the base PQ message
        uint256 ethNonce = extractEthNonce(basePQMessage, 0);
        
        // Verify ETH nonce
        require(ethNonces[currentETHAddress] == ethNonce, "ERR9: Invalid ETH nonce in confirmChangeETHAddress");
        
        // NINTH: Derive public key address from the recovered address
        address publicKeyAddress = recoveredFingerprint;
        
        // TENTH: Verify that the PQ key is currently registered to the current ETH address
        require(addressToEpervierKey[publicKeyAddress] == currentETHAddress, "PQ key not registered to current address");
        
        // ELEVENTH: Check if the new ETH address already has a registered PQ key
        require(addressToEpervierKey[intentNewAddress] == address(0), "New ETH address already has registered PQ key");
        
        // Store the change intent
        changeETHAddressIntents[publicKeyAddress] = ChangeETHAddressIntent({
            newETHAddress: intentNewAddress,
            pqMessage: basePQMessage,
            timestamp: block.timestamp,
            pqNonce: pqKeyNonces[publicKeyAddress] // Use current PQ nonce
        });
        
        // Increment ETH nonce
        ethNonces[currentETHAddress]++;

        emit ChangeETHAddressIntentSubmitted(publicKeyAddress, intentNewAddress, ethNonce);
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
        
        // SECOND: Parse PQ signature components from the ETH message
        bytes memory salt = extractPQSalt(ethMessage);
        uint256[] memory cs1 = extractPQCs1(ethMessage);
        uint256[] memory cs2 = extractPQCs2(ethMessage);
        uint256 hint = extractPQHint(ethMessage);
        bytes memory basePQMessage = extractBasePQMessage(ethMessage);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");
        
        // FOURTH: Parse the new ETH address from the base PQ message
        address intentNewAddress = parseNewETHAddress(basePQMessage);
        require(intentNewAddress != address(0), "Invalid new ETH address");
        
        // FIFTH: Verify that the ETH signature is from the new address
        require(intentNewAddress == recoveredETHAddress, "ETH signature must be from new address");
        
        // SIXTH: Extract ETH nonce from the base PQ message
        uint256 ethNonce = extractEthNonce(basePQMessage, 1); // 1 for confirmation message
        
        // Debug: Log the extracted nonce and verify the message structure
        emit DebugParseStep("confirm_eth_nonce_extracted", ethNonce);
        emit DebugParseStep("confirm_eth_nonce_expected", ethNonces[intentNewAddress]);
        
        // Debug: Let's manually extract the nonce to see what's happening
        emit DebugParseStep("eth_message_length_for_nonce", basePQMessage.length);
        emit DebugParseStep("expected_nonce_position", 32 + 35 + 32);
        
        // Manually extract the nonce bytes to debug
        if (basePQMessage.length >= 32 + 35 + 32 + 32) {
            bytes memory manualNonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                manualNonceBytes[j] = basePQMessage[32 + 35 + 32 + j];
            }
            // Convert to uint256 manually
            uint256 manualNonce = 0;
            for (uint j = 0; j < 32; j++) {
                manualNonce = (manualNonce << 8) | uint8(manualNonceBytes[j]);
            }
            emit DebugParseStep("manual_nonce_extracted", manualNonce);
            
            // Debug: Print the first few bytes of the nonce
            emit DebugParseStep("nonce_byte_0", uint8(manualNonceBytes[0]));
            emit DebugParseStep("nonce_byte_1", uint8(manualNonceBytes[1]));
            emit DebugParseStep("nonce_byte_30", uint8(manualNonceBytes[30]));
            emit DebugParseStep("nonce_byte_31", uint8(manualNonceBytes[31]));
        }
        
        // Verify ETH nonce
        require(ethNonces[intentNewAddress] == ethNonce, "ERR6: Invalid ETH nonce in confirmChangeETHAddress");
        
        // SEVENTH: Derive public key address from the recovered address
        address publicKeyAddress = recoveredFingerprint;
        
        // EIGHTH: Parse the current ETH address from the base PQ message
        address currentETHAddress = parseCurrentETHAddress(basePQMessage);
        require(currentETHAddress != address(0), "Invalid current ETH address");
        
        // NINTH: Verify that the PQ key is currently registered to the current ETH address
        require(addressToEpervierKey[publicKeyAddress] == currentETHAddress, "PQ key not registered to current address");
        
        // TENTH: Check if there's a pending change intent
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[publicKeyAddress];
        require(intent.timestamp != 0, "No pending change intent found");
        
        // ELEVENTH: Verify the new ETH address matches the intent
        require(intent.newETHAddress == intentNewAddress, "ETH address mismatch");
        
        // TWELFTH: Verify intent message consistency
        require(keccak256(intent.pqMessage) == keccak256(basePQMessage), "Intent message mismatch");
        
        // THIRTEENTH: Verify the ETH message contains the correct confirmation text
        require(validateETHConfirmationMessage(ethMessage), "Invalid ETH confirmation message");
        
        // FOURTEENTH: Verify the PQ message contains the correct confirmation text
        require(validatePQConfirmationMessage(basePQMessage), "Invalid PQ confirmation message");

        // Update the mappings
        epervierKeyToAddress[publicKeyAddress] = intentNewAddress;
        addressToEpervierKey[currentETHAddress] = publicKeyAddress;
        
        // Increment nonces
        ethNonces[intentNewAddress]++;
        pqKeyNonces[publicKeyAddress]++;

        // Clear the intent
        delete changeETHAddressIntents[publicKeyAddress];
        
        emit ChangeETHAddressConfirmed(publicKeyAddress, currentETHAddress, intentNewAddress);
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
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");
        
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
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // SECOND: Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress == recoveredAddress, "PQ signature must recover intent address");
        
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
        
        // SEVENTH: Extract ETH signature from the PQ message
        bytes memory ethSignature = extractETHSignature(pqMessage);
        require(ethSignature.length == 65, "Invalid ETH signature length");
        
        // EIGHTH: Parse ETH signature components
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(ethSignature, 32))
            s := mload(add(ethSignature, 64))
            v := byte(0, mload(add(ethSignature, 96)))
        }
        
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
            timestamp: block.timestamp,
            ethNonce: ethNonce
        });
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        emit UnregistrationIntentSubmitted(intentAddress, publicKeyAddress, ethNonce);
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
        bytes memory salt = extractPQSalt(ethMessage);
        uint256[] memory cs1 = extractPQCs1(ethMessage);
        uint256[] memory cs2 = extractPQCs2(ethMessage);
        uint256 hint = extractPQHint(ethMessage);
        bytes memory basePQMessage = extractBasePQMessage(ethMessage);
        
        // THIRD: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");
        
        // FOURTH: Parse the ETH address from the base PQ message
        address intentAddress = parseIntentAddress(basePQMessage);
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");
        
        // FIFTH: Extract ETH nonce from the base PQ message
        uint256 ethNonce = extractEthNonce(basePQMessage, 1); // 1 for confirmation message
        
        // SIXTH: Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "ERR11: Invalid ETH nonce in confirmUnregistration");
        
        // SEVENTH: Verify PQ nonce from message
        uint256 pqNonce = extractPQNonce(basePQMessage, 0);
        require(pqNonce == 0, "PQ nonce must be 0 for unregistration confirmation");
        
        // EIGHTH: Check if there's a pending unregistration intent
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        
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
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");
        
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
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
     */
    function extractBasePQMessageFromPQMessage(bytes memory message) internal pure returns (bytes memory basePQMessage) {
        // Check if message is long enough to contain the pattern + address + pqNonce + ethSignature
        require(message.length >= 32 + 27 + 20 + 32 + 65, "Message too short for base PQ message from PQ message");
        
        // Extract base PQ message (everything before the ETH signature)
        uint256 baseMessageLength = 32 + 27 + 20 + 32; // DOMAIN_SEPARATOR + pattern + address + pqNonce
        
        basePQMessage = new bytes(baseMessageLength);
        for (uint j = 0; j < baseMessageLength; j++) {
            basePQMessage[j] = message[j];
        }
        return basePQMessage;
    }
} 
