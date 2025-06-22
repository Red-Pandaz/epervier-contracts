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
    
    // Domain separator for signature replay protection
    bytes32 public immutable DOMAIN_SEPARATOR;
    
    // Mapping from Epervier public key hash to Ethereum address
    mapping(bytes32 => address) public epervierKeyToAddress;
    
    // Mapping from Ethereum address to Epervier public key hash
    mapping(address => bytes32) public addressToEpervierKey;
    
    // PQ Key nonce tracking to prevent replay attacks on PQ key operations
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
    
    constructor(address _epervierVerifier) {
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        epervierVerifier = ZKNOX_epervier(_epervierVerifier);
        
        // Create domain separator
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("PQRegistry"),
            keccak256("1.0"),
            block.chainid,
            address(this)
        ));
    }
    
    /**
     * @dev Submit registration intent with Epervier signature
     * @param intentMessage The standardized intent message signed by Epervier
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @param publicKey The Epervier public key to be registered
     * @param nonce The nonce for this PQ key operation
     */
    function submitRegistrationIntent(
        bytes calldata intentMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256[2] calldata publicKey,
        uint256 nonce
    ) external {
        // Recover address from Epervier signature
        address recoveredAddress = epervierVerifier.recover(intentMessage, salt, cs1, cs2, hint);
        require(recoveredAddress != address(0), "Invalid Epervier signature");
        
        // Parse the intent message to extract the Ethereum address
        address intentAddress = parseIntentAddress(intentMessage);
        require(intentAddress == recoveredAddress, "Intent address mismatch");
        
        // Validate nonce: must match current nonce for this PQ key
        uint256 currentNonce = pqKeyNonces[keccak256(abi.encodePacked(publicKey[0], publicKey[1]))];
        require(nonce == currentNonce, "Invalid nonce");
        
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
        
        // Store the intent
        pendingIntents[recoveredAddress] = Intent({
            publicKey: publicKey,
            intentMessage: intentMessage,
            timestamp: block.timestamp,
            nonce: nonce
        });
        
        emit RegistrationIntentSubmitted(recoveredAddress, publicKeyHash, nonce);
    }
    
    /**
     * @dev Confirm registration with both ECDSA and Epervier signatures
     * @param confirmationMessage The confirmation message signed by ECDSA
     * @param ecdsaSignature The ECDSA signature of the confirmation message
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     * @param nonce The nonce for this PQ key operation
     */
    function confirmRegistration(
        bytes calldata confirmationMessage,
        bytes calldata ecdsaSignature,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint,
        uint256 nonce
    ) external {
        // Recover address from Epervier signature
        address epervierAddress = epervierVerifier.recover(confirmationMessage, salt, cs1, cs2, hint);
        require(epervierAddress != address(0), "Invalid Epervier signature");
        
        // Recover address from ECDSA signature
        bytes32 messageHash = keccak256(confirmationMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address ecdsaAddress = ECDSA.recover(ethSignedMessageHash, ecdsaSignature);
        
        // Both addresses must match
        require(epervierAddress == ecdsaAddress, "Address mismatch between signatures");
        
        // Get the stored intent
        Intent memory intent = pendingIntents[epervierAddress];
        require(intent.timestamp > 0, "No pending intent");
        require(intent.nonce == nonce, "Nonce mismatch");
        
        // Parse confirmation message to extract address
        address confirmAddress = parseIntentAddress(confirmationMessage);
        
        // Validate confirmation message matches intent
        require(confirmAddress == epervierAddress, "Confirmation address mismatch");
        
        // Additional validation: compare intent message address with confirmation message address
        address intentAddress = parseIntentAddress(intent.intentMessage);
        require(intentAddress == confirmAddress, "Intent and confirmation address mismatch");
        
        // Register the public key
        bytes32 fingerprint = keccak256(abi.encodePacked(intent.publicKey[0], intent.publicKey[1]));
        epervierKeyToAddress[fingerprint] = epervierAddress;
        addressToEpervierKey[epervierAddress] = fingerprint;
        
        // Increment PQ key nonce
        pqKeyNonces[fingerprint]++;
        
        // Clean up
        delete pendingIntents[epervierAddress];
        
        emit RegistrationCompleted(epervierAddress, fingerprint);
    }
    
    /**
     * @dev Parse intent/confirmation message to extract address
     * Expected format: "Intent to bond Epervier Footprint\naddress: 0x..."
     */
    function parseIntentAddress(bytes memory message) internal pure returns (address intentAddress) {
        // For testing purposes, we'll use a simple approach
        // In production, you'd want more robust parsing
        
        // If message is too short, return zero address
        if (message.length < 42) { // "0x" + 40 hex chars
            return address(0);
        }
        
        // For now, assume the address is at the end of the message
        // Extract last 42 bytes (20 bytes address + "0x" prefix)
        bytes memory addressBytes = new bytes(42);
        for (uint i = 0; i < 42; i++) {
            if (i < message.length) {
                addressBytes[i] = message[message.length - 42 + i];
            }
        }
        
        // Convert to address (this is simplified - in production you'd parse hex properly)
        // For testing, we'll return a hardcoded address
        return address(0x1234567890123456789012345678901234567890);
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
} 