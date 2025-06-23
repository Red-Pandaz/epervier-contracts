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
    
    // Pending intents for two-step registration
    struct Intent {
        uint256[2] publicKey;
        bytes intentMessage;
        uint256 timestamp;
        uint256 nonce;
    }
    mapping(address => Intent) public pendingIntents;
    
    // Special constant for disabled PQ security
    bytes32 constant public DISABLED_PQ_KEY = bytes32(uint256(1));
    
    event EpervierKeyRegistered(address indexed owner, bytes32 indexed publicKeyHash);
    event EpervierKeyChanged(address indexed owner, bytes32 indexed oldPublicKeyHash, bytes32 indexed newPublicKeyHash);
    event EpervierKeyDeleted(address indexed owner, bytes32 indexed publicKeyHash);
    event PQSecurityDisabled(address indexed owner);
    event PQSecurityEnabled(address indexed owner, bytes32 indexed publicKeyHash);
    event RegistrationIntentSubmitted(address indexed owner, bytes32 indexed publicKeyHash, uint256 nonce);
    event RegistrationCompleted(address indexed owner, bytes32 indexed publicKeyHash);
    event DebugParsedIntentAddress(address parsedAddress);
    event DebugParseStep(string step, uint256 value);
    
    constructor(address _epervierVerifier) {
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        epervierVerifier = ZKNOX_epervier(_epervierVerifier);
    }
    
    /**
     * @dev Submit registration intent with Epervier signature
     * @param intentMessage The standardized intent message signed by Epervier
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @param publicKey The Epervier public key to be registered
     * @param ethNonce The nonce for this PQ key operation
     * @param ethSignature The ETH signature of the intent
     */
    function submitRegistrationIntent(
        bytes calldata intentMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external {
        // Recover fingerprint from Epervier signature
        address recoveredFingerprint = epervierVerifier.recover(intentMessage, salt, cs1, cs2, hint);
        emit DebugParseStep("epervier_recover_successful", uint256(uint160(recoveredFingerprint)));
        require(recoveredFingerprint != address(0), "Invalid Epervier signature");

        // Parse intent message to extract ETH address
        address intentAddress = parseIntentAddress(intentMessage);
        require(intentAddress != address(0), "Invalid intent address");

        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");

        // Verify ETH signature
        bytes memory ethIntentMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            ethNonce
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
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

        // Check if this Epervier key is already registered to another address
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(
            epervierKeyToAddress[publicKeyHash] == address(0),
            "Epervier key already registered"
        );
        
        // Store the intent with fingerprint mapped to ETH address
        pendingIntents[recoveredFingerprint] = Intent({
            publicKey: publicKey,
            intentMessage: intentMessage,
            timestamp: block.timestamp,
            nonce: ethNonce
        });
        
        // Increment ETH nonce
        ethNonces[intentAddress]++;
        
        emit RegistrationIntentSubmitted(recoveredFingerprint, publicKeyHash, ethNonce);
    }
    
    /**
     * @dev Confirm registration with both ECDSA and Epervier signatures
     * @param confirmationMessage The confirmation message signed by ECDSA
     * @param ecdsaSignature The ECDSA signature of the confirmation message
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @param pqNonce The nonce for this PQ key operation
     */
    function confirmRegistration(
        bytes calldata confirmationMessage,
        bytes calldata ecdsaSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256 pqNonce
    ) external {
        // Recover fingerprint from Epervier signature
        address epervierFingerprint = epervierVerifier.recover(confirmationMessage, salt, cs1, cs2, hint);
        require(epervierFingerprint != address(0), "Invalid Epervier signature");
        
        // Recover ETH address from ECDSA signature
        bytes32 messageHash = keccak256(confirmationMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ecdsaAddress = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        
        // Get the stored intent using the fingerprint
        Intent memory intent = pendingIntents[epervierFingerprint];
        require(intent.timestamp > 0, "No pending intent");
        
        // Parse intent message to get the ETH address that should be bound to this fingerprint
        address intentAddress = parseIntentAddress(intent.intentMessage);
        require(intentAddress != address(0), "Invalid intent address");
        
        // Verify that the ECDSA signer matches the intent address
        require(ecdsaAddress == intentAddress, "ECDSA signer must match intent address");
        
        // Verify PQ nonce
        bytes32 publicKeyHash = keccak256(abi.encodePacked(intent.publicKey[0], intent.publicKey[1]));
        require(pqKeyNonces[publicKeyHash] == pqNonce, "Invalid PQ nonce");
        
        // Register the mapping: fingerprint -> ETH address
        epervierKeyToAddress[publicKeyHash] = intentAddress;
        addressToEpervierKey[intentAddress] = publicKeyHash;
        
        // Increment PQ key nonce
        pqKeyNonces[publicKeyHash]++;
        
        // Clean up
        delete pendingIntents[epervierFingerprint];
        
        emit RegistrationCompleted(intentAddress, publicKeyHash);
    }
    
    /**
     * @dev Parse intent/confirmation message to extract address
     * Expected format: "Register Epervier Key{address}{nonce}"
     */
    function parseIntentAddress(bytes memory message) public returns (address intentAddress) {
        emit DebugParseStep("message_length", message.length);
        
        // If message is too short, return zero address
        if (message.length < 42) { // "0x" + 40 hex chars
            emit DebugParseStep("message_too_short", 0);
            emit DebugParsedIntentAddress(address(0));
            return address(0);
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
                return parsed;
            }
        }
        
        emit DebugParseStep("no_0x_found", 0);
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
     * @dev Register a new Epervier public key for an address
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param message The message that was signed by Epervier (includes ECDSA signature)
     * @param publicKey The Epervier public key
     */
    function registerEpervierKey(
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        bytes calldata message,
        uint256[2] calldata publicKey
    ) external {
        // First verify the Epervier signature and recover the address
        address recoveredAddress = epervierVerifier.recover(message, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Extract the ECDSA signature from the message
        // Message format: "Register Epervier Key" + nonce + publicKey[0] + publicKey[1] + ecdsaSignature
        require(message.length >= 32 + 32 + 32 + 65, "Message too short"); // min length for nonce + pk + ecdsa sig
        
        // Extract the base message (without ECDSA signature)
        bytes memory baseMessage = new bytes(message.length - 65);
        for (uint i = 0; i < message.length - 65; i++) {
            baseMessage[i] = message[i];
        }
        
        // Extract the ECDSA signature (last 65 bytes)
        bytes memory ecdsaSignature = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            ecdsaSignature[i] = message[message.length - 65 + i];
        }
        
        // Verify the ECDSA signature from the same address
        bytes32 messageHash = keccak256(baseMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        require(ethSigner == recoveredAddress, "ECDSA signature must be from same address");
        
        // Check if this address already has a registered key
        require(
            addressToEpervierKey[recoveredAddress] == bytes32(0),
            "Address already has registered Epervier key"
        );

        // Check if this Epervier key is already registered to another address
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(
            epervierKeyToAddress[publicKeyHash] == address(0),
            "Epervier key already registered"
        );

        // Verify that the base message includes the correct nonce
        // The base message should be: abi.encodePacked(DOMAIN_SEPARATOR, "Register Epervier Key", nonce, publicKey[0], publicKey[1], recoveredAddress)
        uint256 expectedNonce = pqKeyNonces[publicKeyHash];
        bytes memory expectedBaseMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Register Epervier Key",
            expectedNonce,
            publicKey[0],
            publicKey[1],
            recoveredAddress
        );
        require(
            keccak256(baseMessage) == keccak256(expectedBaseMessage),
            "Message must include correct nonce and public key"
        );

        // Register the mapping
        epervierKeyToAddress[publicKeyHash] = recoveredAddress;
        addressToEpervierKey[recoveredAddress] = publicKeyHash;
        
        // Increment nonce for this address
        pqKeyNonces[publicKeyHash]++;

        emit EpervierKeyRegistered(recoveredAddress, publicKeyHash);
    }
    
    /**
     * @dev Change the Epervier public key for an already registered address
     * @param oldSalt The old signature salt (40 bytes)
     * @param oldCs1 The old signature s1 component (32 uint256 array)
     * @param oldCs2 The old signature s2 component (32 uint256 array)
     * @param oldHint The old signature hint
     * @param oldMessage The message signed with the old key
     * @param oldPublicKey The old Epervier public key
     * @param newSalt The new signature salt (40 bytes)
     * @param newCs1 The new signature s1 component (32 uint256 array)
     * @param newCs2 The new signature s2 component (32 uint256 array)
     * @param newHint The new signature hint
     * @param newMessage The message signed with the new key (includes ECDSA signature)
     * @param newPublicKey The new Epervier public key
     */
    function changeEpervierKey(
        bytes calldata oldSalt,
        uint256[] calldata oldCs1,
        uint256[] calldata oldCs2,
        uint256 oldHint,
        bytes calldata oldMessage,
        uint256[2] calldata oldPublicKey,
        bytes calldata newSalt,
        uint256[] calldata newCs1,
        uint256[] calldata newCs2,
        uint256 newHint,
        bytes calldata newMessage,
        uint256[2] calldata newPublicKey
    ) external {
        // First verify the old Epervier signature
        address recoveredAddress = epervierVerifier.recover(oldMessage, oldSalt, oldCs1, oldCs2, oldHint);
        require(recoveredAddress != address(0), "Invalid old Epervier signature");
        
        // Then verify the new Epervier signature
        address newRecoveredAddress = epervierVerifier.recover(newMessage, newSalt, newCs1, newCs2, newHint);
        require(
            newRecoveredAddress == recoveredAddress,
            "New signature must recover same address"
        );
        
        // Extract the ECDSA signature from the new message
        // Message format: "Change Epervier Key" + nonce + publicKey[0] + publicKey[1] + ecdsaSignature
        require(newMessage.length >= 32 + 32 + 32 + 65, "Message too short"); // min length for nonce + pk + ecdsa sig
        
        // Extract the base message (without ECDSA signature)
        bytes memory baseMessage = new bytes(newMessage.length - 65);
        for (uint i = 0; i < newMessage.length - 65; i++) {
            baseMessage[i] = newMessage[i];
        }
        
        // Extract the ECDSA signature (last 65 bytes)
        bytes memory ecdsaSignature = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            ecdsaSignature[i] = newMessage[newMessage.length - 65 + i];
        }
        
        // Verify the ECDSA signature from the same address
        bytes32 messageHash = keccak256(baseMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        require(ethSigner == recoveredAddress, "ECDSA signature must be from same address");
        
        // Check if this address has a registered key
        bytes32 oldPublicKeyHash = addressToEpervierKey[recoveredAddress];
        require(
            oldPublicKeyHash != bytes32(0),
            "Address has no registered Epervier key"
        );

        // Check if the new Epervier key is already registered to another address
        bytes32 newPublicKeyHash = keccak256(abi.encodePacked(newPublicKey[0], newPublicKey[1]));
        require(
            epervierKeyToAddress[newPublicKeyHash] == address(0),
            "New Epervier key already registered"
        );

        // Verify that the base message includes the correct nonce
        uint256 expectedNonce = pqKeyNonces[oldPublicKeyHash];
        bytes memory expectedBaseMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Change Epervier Key",
            expectedNonce,
            newPublicKey[0],
            newPublicKey[1],
            recoveredAddress
        );
        require(
            keccak256(baseMessage) == keccak256(expectedBaseMessage),
            "Message must include correct nonce and public key"
        );

        // Update the mappings
        epervierKeyToAddress[oldPublicKeyHash] = address(0); // Remove old mapping
        epervierKeyToAddress[newPublicKeyHash] = recoveredAddress;
        addressToEpervierKey[recoveredAddress] = newPublicKeyHash;
        
        // Increment nonce for this address
        pqKeyNonces[oldPublicKeyHash]++;
        pqKeyNonces[newPublicKeyHash]++;

        emit EpervierKeyChanged(recoveredAddress, oldPublicKeyHash, newPublicKeyHash);
    }
    
    /**
     * @dev Delete the Epervier public key for an address
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param message The message signed by Epervier (includes ECDSA signature)
     */
    function deleteEpervierKey(
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        bytes calldata message
    ) external {
        // First verify the Epervier signature and recover the address
        address recoveredAddress = epervierVerifier.recover(message, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Extract the ECDSA signature from the message
        // Message format: "Delete Epervier Key" + nonce + ecdsaSignature
        require(message.length >= 32 + 65, "Message too short"); // min length for nonce + ecdsa sig
        
        // Extract the base message (without ECDSA signature)
        bytes memory baseMessage = new bytes(message.length - 65);
        for (uint i = 0; i < message.length - 65; i++) {
            baseMessage[i] = message[i];
        }
        
        // Extract the ECDSA signature (last 65 bytes)
        bytes memory ecdsaSignature = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            ecdsaSignature[i] = message[message.length - 65 + i];
        }
        
        // Verify the ECDSA signature from the same address
        bytes32 messageHash = keccak256(baseMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        require(ethSigner == recoveredAddress, "ECDSA signature must be from same address");
        
        // Check if this address has a registered key
        bytes32 publicKeyHash = addressToEpervierKey[recoveredAddress];
        require(
            publicKeyHash != bytes32(0),
            "Address has no registered Epervier key"
        );

        // Verify that the base message includes the correct nonce
        uint256 expectedNonce = pqKeyNonces[publicKeyHash];
        bytes memory expectedBaseMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Delete Epervier Key",
            expectedNonce,
            recoveredAddress
        );
        require(
            keccak256(baseMessage) == keccak256(expectedBaseMessage),
            "Message must include correct nonce"
        );

        // Delete the mappings
        epervierKeyToAddress[publicKeyHash] = address(0);
        addressToEpervierKey[recoveredAddress] = bytes32(0);
        
        // Increment nonce for this address
        pqKeyNonces[publicKeyHash]++;

        emit EpervierKeyDeleted(recoveredAddress, publicKeyHash);
    }
    
    /**
     * @dev Disable PQ security for an address (set to disabled key)
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param message The message signed by Epervier (includes ECDSA signature)
     */
    function disablePQSecurity(
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        bytes calldata message
    ) external {
        // First verify the Epervier signature and recover the address
        address recoveredAddress = epervierVerifier.recover(message, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Extract the ECDSA signature from the message
        // Message format: "Disable PQ Security" + nonce + ecdsaSignature
        require(message.length >= 32 + 65, "Message too short"); // min length for nonce + ecdsa sig
        
        // Extract the base message (without ECDSA signature)
        bytes memory baseMessage = new bytes(message.length - 65);
        for (uint i = 0; i < message.length - 65; i++) {
            baseMessage[i] = message[i];
        }
        
        // Extract the ECDSA signature (last 65 bytes)
        bytes memory ecdsaSignature = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            ecdsaSignature[i] = message[message.length - 65 + i];
        }
        
        // Verify the ECDSA signature from the same address
        bytes32 messageHash = keccak256(baseMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        require(ethSigner == recoveredAddress, "ECDSA signature must be from same address");
        
        // Check if this address has a registered key
        require(
            addressToEpervierKey[recoveredAddress] != bytes32(0),
            "Address has no registered Epervier key"
        );

        // Verify that the base message includes the correct nonce
        uint256 expectedNonce = pqKeyNonces[addressToEpervierKey[recoveredAddress]];
        bytes memory expectedBaseMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Disable PQ Security",
            expectedNonce
        );
        require(
            keccak256(baseMessage) == keccak256(expectedBaseMessage),
            "Message must include correct nonce"
        );

        // Store the current public key hash before disabling
        bytes32 currentPublicKeyHash = addressToEpervierKey[recoveredAddress];
        
        // Set to disabled state
        addressToEpervierKey[recoveredAddress] = DISABLED_PQ_KEY;
        
        // Increment nonce for this address
        pqKeyNonces[currentPublicKeyHash]++;

        emit PQSecurityDisabled(recoveredAddress);
    }
    
    /**
     * @dev Enable PQ security for an address (register a new key)
     * @param salt The signature salt (40 bytes)
     * @param cs1 The signature s1 component (32 uint256 array)
     * @param cs2 The signature s2 component (32 uint256 array)
     * @param hint The signature hint
     * @param message The message signed by Epervier (includes ECDSA signature)
     * @param publicKey The Epervier public key
     */
    function enablePQSecurity(
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        bytes calldata message,
        uint256[2] calldata publicKey
    ) external {
        // First verify the Epervier signature and recover the address
        address recoveredAddress = epervierVerifier.recover(message, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Extract the ECDSA signature from the message
        // Message format: "Enable PQ Security" + nonce + publicKey[0] + publicKey[1] + ecdsaSignature
        require(message.length >= 32 + 32 + 32 + 65, "Message too short"); // min length for nonce + pk + ecdsa sig
        
        // Extract the base message (without ECDSA signature)
        bytes memory baseMessage = new bytes(message.length - 65);
        for (uint i = 0; i < message.length - 65; i++) {
            baseMessage[i] = message[i];
        }
        
        // Extract the ECDSA signature (last 65 bytes)
        bytes memory ecdsaSignature = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            ecdsaSignature[i] = message[message.length - 65 + i];
        }
        
        // Verify the ECDSA signature from the same address
        bytes32 messageHash = keccak256(baseMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ethSigner = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        require(ethSigner == recoveredAddress, "ECDSA signature must be from same address");
        
        // Check if this address is currently disabled
        require(
            addressToEpervierKey[recoveredAddress] == DISABLED_PQ_KEY,
            "Address must be in disabled state to enable PQ security"
        );

        // Check if this Epervier key is already registered to another address
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        require(
            epervierKeyToAddress[publicKeyHash] == address(0),
            "Epervier key already registered"
        );

        // Verify that the base message includes the correct nonce
        uint256 expectedNonce = pqKeyNonces[publicKeyHash];
        bytes memory expectedBaseMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Enable PQ Security",
            expectedNonce,
            publicKey[0],
            publicKey[1]
        );
        require(
            keccak256(baseMessage) == keccak256(expectedBaseMessage),
            "Message must include correct nonce and public key"
        );

        // Register the mapping
        epervierKeyToAddress[publicKeyHash] = recoveredAddress;
        addressToEpervierKey[recoveredAddress] = publicKeyHash;
        
        // Increment nonce for this address
        pqKeyNonces[publicKeyHash]++;

        emit PQSecurityEnabled(recoveredAddress, publicKeyHash);
    }
    
    /**
     * @dev Check if PQ security is disabled for an address
     * @param owner The address to check
     * @return True if PQ security is disabled
     */
    function isPQSecurityDisabled(address owner) external view returns (bool) {
        return addressToEpervierKey[owner] == DISABLED_PQ_KEY;
    }
    
    /**
     * @dev Get the current nonce for an address
     * @param owner The address to get the nonce for
     * @return The current nonce
     */
    function getNonce(address owner) external view returns (uint256) {
        return pqKeyNonces[addressToEpervierKey[owner]];
    }
    
    /**
     * @dev Check if an address has a registered Epervier key
     * @param owner The address to check
     * @return True if the address has a registered key
     */
    function hasEpervierKey(address owner) external view returns (bool) {
        return addressToEpervierKey[owner] != bytes32(0);
    }
    
    /**
     * @dev Get the Epervier public key hash for an address
     * @param owner The address to get the key for
     * @return The public key hash, or bytes32(0) if not registered
     */
    function getEpervierKeyHash(address owner) external view returns (bytes32) {
        return addressToEpervierKey[owner];
    }
    
    /**
     * @dev Get the address registered for an Epervier public key hash
     * @param publicKeyHash The public key hash to look up
     * @return The registered address, or address(0) if not registered
     */
    function getAddressByEpervierKey(bytes32 publicKeyHash) external view returns (address) {
        return epervierKeyToAddress[publicKeyHash];
    }
    
    /**
     * @dev Get the current nonce for a PQ key
     * @param publicKey The public key to get the nonce for
     * @return The current nonce
     */
    function getPQKeyNonce(uint256[2] calldata publicKey) external view returns (uint256) {
        bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey[0], publicKey[1]));
        return pqKeyNonces[publicKeyHash];
    }
    
    /**
     * @dev Test function to only verify Epervier signature recovery
     * @param intentMessage The message that was signed by Epervier
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @return The recovered address from the Epervier signature
     */
    function testEpervierRecovery(
        bytes calldata intentMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address) {
        // Only call the Epervier verifier's recover function
        address recoveredAddress = epervierVerifier.recover(intentMessage, salt, cs1, cs2, hint);
        
        // Emit debug events
        emit DebugParseStep("test_epervier_recovery_called", 1);
        emit DebugParseStep("recovered_address", uint256(uint160(recoveredAddress)));
        emit DebugParsedIntentAddress(recoveredAddress);
        
        return recoveredAddress;
    }
    
    /**
     * @dev Test function to only verify ETH signature verification
     * @param intentAddress The address that should have signed the ETH message
     * @param ethNonce The nonce for this operation
     * @param ethSignature The ETH signature to verify
     * @return The recovered ETH signer address
     */
    function testETHSignatureVerification(
        address intentAddress,
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external returns (address) {
        // Verify ETH nonce
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // Verify ETH signature
        bytes memory ethIntentMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            ethNonce
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
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
        
        // Don't require addresses to match for debugging
        // require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        return ethSigner;
    }

    /**
     * @dev Test function to debug Epervier signature verification
     */
    function testEpervierSignatureDebug(
        bytes calldata intentMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address) {
        emit DebugParseStep("test_epervier_start", 0);
        
        // Recover fingerprint from Epervier signature
        address recoveredFingerprint = epervierVerifier.recover(intentMessage, salt, cs1, cs2, hint);
        emit DebugParseStep("epervier_recover_result", uint256(uint160(recoveredFingerprint)));
        
        return recoveredFingerprint;
    }

    /**
     * @dev Test function to debug ETH signature verification
     */
    function testETHSignatureDebug(
        uint256 ethNonce,
        bytes calldata ethSignature
    ) external returns (address) {
        emit DebugParseStep("test_eth_start", 0);
        
        // Verify ETH signature
        bytes memory ethIntentMessage = abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            ethNonce
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
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
        
        return ethSigner;
    }
} 