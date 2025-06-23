// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title PQRegistry
 * @dev Registry for Epervier public keys with nonce tracking to prevent replay attacks
 * Requires both Epervier signature and ECDSA signature from the same address
 */
contract PQRegistry {
    ZKNOX_epervier public immutable epervierVerifier;
    
    // Domain separator for replay protection
    bytes32 public constant DOMAIN_SEPARATOR = keccak256("PQRegistry");
    
    // Mapping from Epervier public key hash to Ethereum address
    mapping(bytes32 => address) public epervierKeyToAddress;
    
    // Mapping from Ethereum address to Epervier public key hash
    mapping(address => bytes32) public addressToEpervierKey;
    
    // Nonces for ETH addresses (per domain)
    mapping(address => uint256) public ethNonces;
    
    // Nonces for PQ keys (existing)
    mapping(bytes32 => uint256) public pqKeyNonces;
    
    // Pending intents for two-step registration - ETH address controls their intent
    struct Intent {
        bytes32 pqFingerprint;
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
    mapping(bytes32 => ChangeETHAddressIntent) public changeETHAddressIntents;
    
    // Special constant for disabled PQ security
    bytes32 constant public DISABLED_PQ_KEY = bytes32(uint256(1));
    
    struct UnregistrationIntent {
        uint256[2] publicKey;
        bytes32 publicKeyHash;
        bytes pqMessage;
        uint256 timestamp;
        uint256 ethNonce;
    }
    
    mapping(address => UnregistrationIntent) public unregistrationIntents;
    
    event EpervierKeyDeleted(address indexed owner, bytes32 indexed publicKeyHash);
    event PQSecurityDisabled(address indexed owner);
    event PQSecurityEnabled(address indexed owner, bytes32 indexed publicKeyHash);
    event RegistrationIntentSubmitted(address indexed ethAddress, bytes32 indexed pqFingerprint, uint256 ethNonce);
    event RegistrationConfirmed(address indexed ethAddress, bytes32 indexed pqFingerprint);
    event RegistrationIntentRemoved(address indexed ethAddress);
    event IntentRemoved(address indexed owner);
    event ChangeETHAddressIntentSubmitted(bytes32 indexed pqFingerprint, address indexed newETHAddress, uint256 pqNonce);
    event ChangeETHAddressConfirmed(bytes32 indexed pqFingerprint, address indexed oldETHAddress, address indexed newETHAddress);
    event ChangeETHAddressIntentRemoved(bytes32 indexed pqFingerprint);
    event UnregistrationIntentSubmitted(address indexed ethAddress, bytes32 indexed pqFingerprint, uint256 ethNonce);
    event UnregistrationConfirmed(address indexed ethAddress, bytes32 indexed pqFingerprint);
    event UnregistrationIntentRemoved(address indexed ethAddress);
    event DebugParsedIntentAddress(address parsedAddress);
    event DebugParseStep(string step, uint256 value);
    
    constructor(address _epervierVerifier) {
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        epervierVerifier = ZKNOX_epervier(_epervierVerifier);
    }
    
    /**
     * @dev Submit registration intent with nested signatures
     * @param pqMessage The PQ message signed by Epervier
     * @param pqSignature The Epervier signature components
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @param publicKey The Epervier public key to be registered
     * @param ethNonce The nonce for this ETH operation
     * @param ethSignature The ETH signature of the nested message
     */
    function submitRegistrationIntent(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external {
        // FIRST: Verify the PQ signature and recover the ETH address
        // This call verifies that (salt, cs1, cs2, hint) is a valid signature of pqMessage
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress != address(0), "Invalid intent address");
        
        // CRITICAL: Verify that the recovered address from PQ signature matches the address in the message
        require(recoveredAddress == intentAddress, "PQ signature must recover intent address");
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Verify PQ message format and extract PQ nonce
        uint256 pqNonce = extractPQNonce(pqMessage);
        require(pqNonce == 0, "PQ nonce must be 0 for registration intent");
        
        // Verify public key hash
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(
            epervierKeyToAddress[publicKeyHash] == address(0),
            "Epervier key already registered"
        );
        
        // SECOND: Create and verify the ETH message that includes the PQ message
        // Note: We don't include the raw PQ signature components in the ETH message
        // Instead, we include the PQ message that was signed
        bytes memory ethMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            ethNonce,
            pqMessage // Include the PQ message that was signed
        );
        
        // Debug: Show the ETH message hash being created
        bytes32 ethMessageHash = keccak256(ethMessage);
        emit DebugParseStep("contract_eth_message_hash", uint256(ethMessageHash));
        
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        // Debug logging
        emit DebugParseStep("ethMessageHash", uint256(ethMessageHash));
        emit DebugParseStep("ethSignedMessageHash", uint256(ethSignedMessageHash));
        emit DebugParseStep("ethSignature_length", ethSignature.length);
        
        // Parse signature components for debugging
        require(ethSignature.length == 65, "Invalid signature length");
        bytes32 r = bytes32(ethSignature[:32]);
        bytes32 s = bytes32(ethSignature[32:64]);
        uint8 v = uint8(ethSignature[64]);
        emit DebugParseStep("signature_r", uint256(r));
        emit DebugParseStep("signature_s", uint256(s));
        emit DebugParseStep("signature_v", v);
        
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ethSignature);
        emit DebugParseStep("recovered_eth_signer", uint256(uint160(ethSigner)));
        emit DebugParsedIntentAddress(ethSigner);

        // Verify that the ETH signer matches the intent address
        require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        // Store the intent
        Intent memory newIntent = Intent({
            pqFingerprint: publicKeyHash,
            publicKey: publicKey,
            intentMessage: pqMessage, // Store the PQ message
            timestamp: block.timestamp,
            ethNonce: ethNonce
        });
        
        pendingIntents[intentAddress] = newIntent;
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        emit RegistrationIntentSubmitted(intentAddress, publicKeyHash, ethNonce);
    }
    
    /**
     * @dev Confirm registration with nested signatures
     * @param pqMessage The PQ message signed by Epervier
     * @param pqSignature The Epervier signature components
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @param publicKey The Epervier public key to be registered
     * @param ethNonce The nonce for this ETH operation
     * @param ethSignature The ETH signature of the nested message
     */
    function confirmRegistration(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external {
        // First verify the PQ signature and recover the address
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        emit DebugParseStep("epervier_recover_successful", uint256(uint160(recoveredFingerprint)));
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");

        // Parse PQ message to extract ETH address
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress != address(0), "Invalid intent address");

        // Check if there's a pending intent first
        Intent memory intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found");

        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Verify PQ message format and extract PQ nonce
        uint256 pqNonce = extractPQNonce(pqMessage);
        require(pqNonce == 0, "PQ nonce must be 0 for registration confirmation");
        
        // Verify the intent message matches the current pqMessage
        require(keccak256(intent.intentMessage) == keccak256(pqMessage), "Intent message mismatch");

        // Create the ETH message that includes the PQ message
        bytes memory ethMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Confirm registration",
            ethNonce,
            pqMessage // Include the PQ message that was signed, not the raw signature components
        );
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        // Debug logging
        emit DebugParseStep("ethMessageHash", uint256(ethMessageHash));
        emit DebugParseStep("ethSignedMessageHash", uint256(ethSignedMessageHash));
        emit DebugParseStep("ethSignature_length", ethSignature.length);
        
        // Parse signature components for debugging
        require(ethSignature.length == 65, "Invalid signature length");
        bytes32 r = bytes32(ethSignature[:32]);
        bytes32 s = bytes32(ethSignature[32:64]);
        uint8 v = uint8(ethSignature[64]);
        emit DebugParseStep("signature_r", uint256(r));
        emit DebugParseStep("signature_s", uint256(s));
        emit DebugParseStep("signature_v", v);
        
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ethSignature);
        emit DebugParseStep("recovered_eth_signer", uint256(uint160(ethSigner)));
        emit DebugParsedIntentAddress(ethSigner);

        // Verify that the ETH signer matches the intent address
        require(ethSigner == intentAddress, "ETH signature must be from intent address");

        // Verify the intent matches
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(intent.pqFingerprint == publicKeyHash, "Intent mismatch");

        // Register the key
        epervierKeyToAddress[publicKeyHash] = intentAddress;
        addressToEpervierKey[intentAddress] = publicKeyHash;

        // Clear the pending intent
        delete pendingIntents[intentAddress];

        // Increment ETH nonce
        ethNonces[intentAddress]++;

        emit RegistrationConfirmed(intentAddress, publicKeyHash);
    }
    
    /**
     * @dev Remove a pending registration intent
     * @param pqMessage The message signed by the PQ key (includes ETH address and nonce)
     * @param pqSignature The PQ signature of the message
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param ethNonce The ETH nonce for replay protection
     */
    function removeIntent(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256 ethNonce
    ) external {
        // Verify the PQ signature and recover the ETH address
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress == recoveredAddress, "PQ signature must recover intent address");
        
        // Check if there's a pending intent
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found");
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Clear the intent
        delete pendingIntents[intentAddress];
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        emit RegistrationIntentRemoved(intentAddress);
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
    /**
     * @dev Extract fingerprint from PQ message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
     */
    function extractFingerprintFromMessage(bytes memory message) internal pure returns (bytes32 fingerprint) {
        // Look for the fingerprint at the end of the message (last 32 bytes)
        require(message.length >= 32, "Message too short for fingerprint");
        
        bytes memory fingerprintBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            fingerprintBytes[i] = message[message.length - 32 + i];
        }
        
        return bytes32(fingerprintBytes);
    }
    
    /**
     * @dev Extract PQ nonce from PQ message
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
     */
    function extractPQNonce(bytes memory message) internal pure returns (uint256 pqNonce) {
        // Check if message is long enough to contain the pattern + address + nonce
        require(message.length >= 32 + 27 + 20 + 32, "Message too short for PQ nonce");
        
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
            bool found = true;
            for (uint j = 0; j < 27; j++) {
                if (message[i + j] != keyPattern[j]) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                // Extract the last 32 bytes as the PQ nonce
                bytes memory nonceBytes = new bytes(32);
                for (uint j = 0; j < 32; j++) {
                    nonceBytes[j] = message[message.length - 32 + j];
                }
                
                // Convert bytes to uint256
                uint256 nonce = 0;
                for (uint j = 0; j < 32; j++) {
                    nonce = (nonce << 8) | uint8(nonceBytes[j]);
                }
                return nonce;
            }
        }
        
        revert("PQ nonce not found in message");
    }
    
    function submitChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        address newETHAddress,
        uint256 pqNonce
    ) external {
        // Verify the PQ signature and recover the current ETH address
        address currentETHAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(currentETHAddress != address(0), "Invalid Epervier signature");
        
        // Parse the new ETH address from the PQ message
        address intentNewAddress = parseIntentAddress(pqMessage);
        require(intentNewAddress == newETHAddress, "PQ message must contain new ETH address");
        
        // CRITICAL: Verify that the recovered address from PQ signature matches the current registered address
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(epervierKeyToAddress[publicKeyHash] == currentETHAddress, "PQ key not registered to current address");
        
        // Verify PQ nonce from message matches provided nonce
        uint256 extractedPQNonce = extractPQNonce(pqMessage);
        require(extractedPQNonce == pqNonce, "PQ nonce mismatch");
        require(pqKeyNonces[publicKeyHash] == pqNonce, "Invalid PQ nonce");
        
        // Check if the new ETH address already has a registered PQ key
        require(addressToEpervierKey[newETHAddress] == bytes32(0), "New ETH address already has registered PQ key");
        
        // Store the change intent
        changeETHAddressIntents[publicKeyHash] = ChangeETHAddressIntent({
            newETHAddress: newETHAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp,
            pqNonce: pqNonce
        });
        
        // Increment PQ nonce
        pqKeyNonces[publicKeyHash]++;
        
        emit ChangeETHAddressIntentSubmitted(publicKeyHash, newETHAddress, pqNonce);
    }
    
    function confirmChangeETHAddress(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        address newETHAddress,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external {
        // Verify the PQ signature and recover the current ETH address
        address currentETHAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(currentETHAddress != address(0), "Invalid Epervier signature");
        
        // Parse the new ETH address from the PQ message
        address intentNewAddress = parseIntentAddress(pqMessage);
        require(intentNewAddress == newETHAddress, "PQ message must contain new ETH address");
        
        // CRITICAL: Verify that the recovered address from PQ signature matches the current registered address
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(epervierKeyToAddress[publicKeyHash] == currentETHAddress, "PQ key not registered to current address");
        
        // Check if there's a pending change intent
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[publicKeyHash];
        require(intent.timestamp != 0, "No pending change intent found");
        
        // Verify the new ETH address matches the intent
        require(intent.newETHAddress == newETHAddress, "ETH address mismatch");
        
        // Verify PQ nonce from message matches intent nonce
        uint256 extractedPQNonce = extractPQNonce(pqMessage);
        require(extractedPQNonce == intent.pqNonce, "PQ nonce mismatch");
        
        // Verify intent message consistency
        require(keccak256(intent.pqMessage) == keccak256(pqMessage), "Intent message mismatch");
        
        // Create the ETH message that includes the PQ message
        bytes memory ethMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Confirm change ETH Address",
            ethNonce,
            pqMessage // Include the PQ message that was signed
        );
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        // Verify the ETH signature from the new address
        require(ethSignature.length == 65, "Invalid ETH signature length");
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ethSignature);
        require(ethSigner == newETHAddress, "ETH signature must be from new address");
        
        // Verify ETH nonce
        require(ethNonces[newETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // Update the mappings
        epervierKeyToAddress[publicKeyHash] = newETHAddress;
        addressToEpervierKey[currentETHAddress] = bytes32(0); // Remove old mapping
        addressToEpervierKey[newETHAddress] = publicKeyHash;
        
        // Increment nonces
        ethNonces[newETHAddress]++;
        pqKeyNonces[publicKeyHash]++;

        // Clear the intent
        delete changeETHAddressIntents[publicKeyHash];
        
        emit ChangeETHAddressConfirmed(publicKeyHash, currentETHAddress, newETHAddress);
    }
    
    function removeChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 pqNonce
    ) external {
        // Verify the PQ signature and recover the current ETH address
        address currentETHAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(currentETHAddress != address(0), "Invalid Epervier signature");
        
        // Check if this PQ key is currently registered
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(epervierKeyToAddress[publicKeyHash] == currentETHAddress, "PQ key not registered to current address");
        
        // Check if there's a pending change intent
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[publicKeyHash];
        require(intent.timestamp != 0, "No pending change intent found");
        
        // Verify PQ nonce
        require(pqKeyNonces[publicKeyHash] == pqNonce, "Invalid PQ nonce");
        
        // Clear the intent
        delete changeETHAddressIntents[publicKeyHash];
        
        // Increment PQ nonce
        pqKeyNonces[publicKeyHash]++;

        emit ChangeETHAddressIntentRemoved(publicKeyHash);
    }
    
    /**
     * @dev Submit unregistration intent with nested signatures
     * @param pqMessage The PQ message signed by Epervier (includes ETH address and nonce)
     * @param pqSignature The PQ signature of the message
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param publicKey The Epervier public key to be unregistered
     * @param ethNonce The ETH nonce for replay protection
     * @param ethSignature The ETH signature of the nested message
     */
    function submitUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external {
        // Verify the PQ signature and recover the ETH address
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress == recoveredAddress, "PQ signature must recover intent address");
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Verify PQ nonce from message
        uint256 pqNonce = extractPQNonce(pqMessage);
        require(pqNonce == 0, "PQ nonce must be 0 for unregistration intent");
        
        // Check if this address has a registered key
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(addressToEpervierKey[intentAddress] == publicKeyHash, "Address has no registered Epervier key");
        
        // Create the ETH message that includes the PQ message
        bytes memory ethMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to unregister from PQ fingerprint",
            ethNonce,
            pqMessage // Include the PQ message that was signed
        );
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        // Verify the ETH signature
        require(ethSignature.length == 65, "Invalid ETH signature length");
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ethSignature);
        require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        // Store the unregistration intent
        UnregistrationIntent memory newIntent = UnregistrationIntent({
            publicKey: publicKey,
            publicKeyHash: publicKeyHash,
            pqMessage: pqMessage,
            timestamp: block.timestamp,
            ethNonce: ethNonce
        });
        
        unregistrationIntents[intentAddress] = newIntent;
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        emit UnregistrationIntentSubmitted(intentAddress, publicKeyHash, ethNonce);
    }
    
    /**
     * @dev Confirm unregistration with nested signatures
     * @param pqMessage The PQ message signed by Epervier (includes ETH address and nonce)
     * @param pqSignature The PQ signature of the message
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param publicKey The Epervier public key to be unregistered
     * @param ethNonce The ETH nonce for replay protection
     * @param ethSignature The ETH signature of the nested message
     */
    function confirmUnregistration(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external {
        // Verify the PQ signature and recover the ETH address
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress == recoveredAddress, "PQ signature must recover intent address");
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Verify PQ nonce from message
        uint256 pqNonce = extractPQNonce(pqMessage);
        require(pqNonce == 0, "PQ nonce must be 0 for unregistration confirmation");
        
        // Check if there's a pending unregistration intent
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        
        // Verify the public key matches the intent
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(intent.publicKeyHash == publicKeyHash, "Public key mismatch");
        
        // Verify intent message consistency
        require(keccak256(intent.pqMessage) == keccak256(pqMessage), "Intent message mismatch");
        
        // Create the ETH message that includes the PQ message
        bytes memory ethMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Confirm unregistration from PQ fingerprint",
            ethNonce,
            pqMessage // Include the PQ message that was signed
        );
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        // Verify the ETH signature
        require(ethSignature.length == 65, "Invalid ETH signature length");
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ethSignature);
        require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        // Remove the mappings
        epervierKeyToAddress[publicKeyHash] = address(0);
        addressToEpervierKey[intentAddress] = bytes32(0);
        
        // Clear the intent
        delete unregistrationIntents[intentAddress];
        
        // Increment nonces
        ethNonces[intentAddress]++;
        pqKeyNonces[publicKeyHash]++;

        emit UnregistrationConfirmed(intentAddress, publicKeyHash);
    }
    
    /**
     * @dev Remove a pending unregistration intent
     * @param pqMessage The message signed by the PQ key (includes ETH address and nonce)
     * @param pqSignature The PQ signature of the message
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param ethNonce The ETH nonce for replay protection
     */
    function removeUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata pqSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256 ethNonce
    ) external {
        // Verify the PQ signature and recover the ETH address
        address recoveredAddress = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Parse the ETH address from the PQ message
        address intentAddress = parseIntentAddress(pqMessage);
        require(intentAddress == recoveredAddress, "PQ signature must recover intent address");
        
        // Check if there's a pending unregistration intent
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Clear the intent
        delete unregistrationIntents[intentAddress];
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        emit UnregistrationIntentRemoved(intentAddress);
    }
} 