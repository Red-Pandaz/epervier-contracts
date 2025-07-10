// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./RegistryStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract UnregistrationLogicContract {
    using ECDSA for bytes32;
    using RegistryStorage for RegistryStorage.Layout;
    
    // Events
    event UnregistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint);
    event UnregistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event UnregistrationIntentRemoved(address indexed pqFingerprint);
    
    function submitUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address ethAddress, address pqFingerprint) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ unregistration intent message format
        require(storage_s.messageParser.validatePQUnregistrationIntentMessage(pqMessage), "Invalid PQ unregistration intent message");
        
        // STEP 3: Parse the PQ unregistration intent message to extract the base ETH message
        (
            address currentEthAddress,
            uint256 pqNonce,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = storage_s.messageParser.parsePQUnregistrationIntentMessage(pqMessage, storage_s.DOMAIN_SEPARATOR);
        
        // STEP 4: Parse the base ETH unregistration intent message
        (address ethMessagePqFingerprint, uint256 ethNonce) = storage_s.messageParser.parseBaseETHUnregistrationIntentMessage(baseETHMessage);
        
        // STEP 5: Validate the base ETH unregistration intent message format
        require(storage_s.messageParser.validateBaseETHUnregistrationIntentMessage(baseETHMessage), "Invalid base ETH unregistration intent message");
        
        // STEP 6: State validation - Check ETH address mismatch FIRST, then if PQ fingerprint is registered
        address registeredETHAddress = storage_s.epervierKeyToAddress[recoveredFingerprint];
        require(registeredETHAddress == currentEthAddress, "ETH Address mismatch: PQ message vs stored registration");
        require(registeredETHAddress != address(0), "PQ fingerprint not registered");
        
        // STEP 7: Cross-reference validation
        require(ethMessagePqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // STEP 8: Verify the ETH signature using EIP712 (after address validation)
        bytes32 structHash = storage_s.signatureExtractor.getUnregistrationIntentStructHash(recoveredFingerprint, ethNonce);
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        require(recoveredETHAddress == currentEthAddress, "ETH signature must be from intent address");
        
        // STEP 9: State validation - Check for change intent conflicts first
        require(storage_s.changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        
        // STEP 10: State validation - Check for unregistration conflicts (ETH address mapping first)
        require(storage_s.ethAddressToUnregistrationFingerprint[registeredETHAddress] == address(0), "ETH Address has pending unregistration intent");
        require(storage_s.unregistrationIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending unregistration intent");
        
        // STEP 11: Nonce validation
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(storage_s.ethNonces[registeredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 12: Store the intent
        RegistryStorage.UnregistrationIntent memory intent = RegistryStorage.UnregistrationIntent({
            timestamp: block.timestamp,
            publicKey: [uint256(0), uint256(0)], // Placeholder
            publicKeyAddress: address(0), // Placeholder
            pqMessage: pqMessage
        });
        storage_s.unregistrationIntents[recoveredFingerprint] = intent;
        
        // STEP 13: Store the bidirectional mapping
        storage_s.ethAddressToUnregistrationFingerprint[registeredETHAddress] = recoveredFingerprint;
        
        // STEP 14: Increment nonces
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        storage_s.ethNonces[registeredETHAddress]++;
        
        emit UnregistrationIntentSubmitted(registeredETHAddress, recoveredFingerprint);
        
        return (registeredETHAddress, recoveredFingerprint);
    }
    
    function confirmUnregistration(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address ethAddress, address pqFingerprint) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Parse the ETH unregistration confirmation message
        uint256 ethNonce = storage_s.messageParser.extractEthNonce(ethMessage, 0);
        
        // STEP 2: Extract PQ signature components
        bytes memory salt = storage_s.messageParser.extractPQSalt(ethMessage, 2);
        uint256[] memory cs1 = storage_s.messageParser.extractPQCs1(ethMessage, 2);
        uint256[] memory cs2 = storage_s.messageParser.extractPQCs2(ethMessage, 2);
        uint256 hint = storage_s.messageParser.extractPQHint(ethMessage, 2);
        bytes memory basePQMessage = storage_s.messageParser.extractBasePQMessage(ethMessage, 2);
        
        // STEP 3: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        
        // STEP 4: Parse the ETH address from the confirmation message
        address fingerprintAddress = storage_s.messageParser.parseETHAddressFromETHUnregistrationConfirmationMessage(ethMessage);
        
        // STEP 5: Cross-reference validation
        require(fingerprintAddress == recoveredFingerprint, "Fingerprint address mismatch: ETH message vs recovered PQ signature");
        
        // STEP 6: Parse the base PQ unregistration confirmation message
        (address basePQEthAddress, ) = storage_s.messageParser.parseBasePQUnregistrationConfirmMessage(basePQMessage, storage_s.DOMAIN_SEPARATOR);
        
        // STEP 7: Get the registered ETH address and validate (check registration BEFORE pending intent)
        address registeredETHAddress = storage_s.epervierKeyToAddress[recoveredFingerprint];
        require(registeredETHAddress == basePQEthAddress, "ETH Address not registered to PQ fingerprint");
        require(registeredETHAddress != address(0), "PQ fingerprint not registered");
        
        // STEP 8: State validation - Check if there's a pending intent
        RegistryStorage.UnregistrationIntent storage intent = storage_s.unregistrationIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending unregistration intent found for ETH Address");
        
        // STEP 9: Verify the ETH signature using EIP712
        uint256[32] memory cs1Array;
        uint256[32] memory cs2Array;
        for (uint i = 0; i < 32; i++) {
            cs1Array[i] = cs1[i];
            cs2Array[i] = cs2[i];
        }
        
        bytes32 structHash = storage_s.signatureExtractor.getUnregistrationConfirmationStructHash(
            recoveredFingerprint,
            basePQMessage,
            salt,
            cs1Array,
            cs2Array,
            hint,
            ethNonce
        );
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        require(recoveredETHAddress == registeredETHAddress, "ETH signature must be from registered address");
        
        // STEP 10: Validate message formats
        require(storage_s.messageParser.validateETHUnregistrationConfirmationMessage(ethMessage), "Invalid ETH confirmation message");
        require(storage_s.messageParser.validatePQUnregistrationConfirmationMessage(basePQMessage), "Invalid PQ confirmation message");
        
        // STEP 11: Nonce validation
        uint256 pqNonce = storage_s.messageParser.extractPQNonce(basePQMessage, 0);
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(storage_s.ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 12: Complete the unregistration
        delete storage_s.epervierKeyToAddress[recoveredFingerprint];
        delete storage_s.addressToEpervierKey[recoveredETHAddress];
        
        // STEP 13: Clear the pending intent and bidirectional mapping
        delete storage_s.unregistrationIntents[recoveredFingerprint];
        delete storage_s.ethAddressToUnregistrationFingerprint[recoveredETHAddress];
        
        // STEP 14: Increment nonces
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        storage_s.ethNonces[recoveredETHAddress]++;
        
        emit UnregistrationConfirmed(recoveredETHAddress, recoveredFingerprint);
        
        return (recoveredETHAddress, recoveredFingerprint);
    }
    
    function removeUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address pqFingerprint) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Extract PQ nonce from the PQ message
        uint256 pqNonce = storage_s.messageParser.extractPQNonceFromRemoveMessage(pqMessage);
        
        // STEP 3: Parse the ETH Address from the PQ message
        (address intentAddress, ) = storage_s.messageParser.parsePQRemoveUnregistrationIntentMessage(pqMessage, storage_s.DOMAIN_SEPARATOR);
        require(intentAddress != address(0), "Invalid intent address");
        
        // STEP 4: Cross-validate PQ signer with intent ownership
        address publicKeyAddress = recoveredFingerprint;
        address registeredETHAddress = storage_s.epervierKeyToAddress[recoveredFingerprint];
        
        // Check if the PQ key is even registered
        require(registeredETHAddress != address(0), "PQ key mismatch");
        
        // Check if the ETH address in the message matches the registered address
        require(registeredETHAddress == intentAddress, "No pending unregistration intent found");
        
        // STEP 5: State validation
        RegistryStorage.UnregistrationIntent storage intent = storage_s.unregistrationIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        
        // STEP 5: Nonce validation
        require(storage_s.pqKeyNonces[publicKeyAddress] == pqNonce, "Invalid PQ nonce");
        
        // STEP 6: Verify the PQ message contains the correct removal text
        require(storage_s.messageParser.validatePQUnregistrationRemovalMessage(pqMessage), "Invalid PQ removal message");
        
        // STEP 7: Clear the intent
        delete storage_s.unregistrationIntents[recoveredFingerprint];
        
        // Use the already obtained registered ETH address for proper cleanup
        delete storage_s.ethAddressToUnregistrationFingerprint[registeredETHAddress];
        
        // STEP 8: Increment nonce
        storage_s.pqKeyNonces[publicKeyAddress]++;
        
        emit UnregistrationIntentRemoved(publicKeyAddress);
        
        return publicKeyAddress;
    }
} 