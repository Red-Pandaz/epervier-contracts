// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./RegistryStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ChangeAddressLogicContract {
    using ECDSA for bytes32;
    using RegistryStorage for RegistryStorage.Layout;
    
    // Events
    event ChangeETHAddressIntentSubmitted(address indexed pqFingerprint, address indexed newETHAddress, uint256 indexed ethNonce);
    event ChangeETHAddressConfirmed(address indexed pqFingerprint, address indexed oldETHAddress, address indexed newETHAddress);
    event ChangeETHAddressIntentRemoved(address indexed pqFingerprint);
    
    function submitChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address oldEthAddress, address newEthAddress, address pqFingerprint) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ change address intent message format
        require(storage_s.messageParser.validatePQChangeETHAddressIntentMessage(pqMessage), "Invalid PQ change address intent message");
        
        // STEP 3: Parse the PQ change address intent message
        (
            address oldEthAddr,
            address newEthAddr,
            uint256 pqNonce,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = storage_s.messageParser.parsePQChangeETHAddressIntentMessage(pqMessage, storage_s.DOMAIN_SEPARATOR);
        
        // STEP 4: Parse the base ETH change address intent message
        (address ethMessagePqFingerprint, address ethMessageNewEthAddress, uint256 ethNonce) = storage_s.messageParser.parseBaseETHChangeETHAddressIntentMessage(baseETHMessage);
        
        // STEP 5: Validate the base ETH change address intent message format
        require(storage_s.messageParser.validateBaseETHChangeETHAddressIntentMessage(baseETHMessage), "Invalid base ETH change address intent message");
        
        // STEP 6: Cross-reference validation
        require(ethMessagePqFingerprint == recoveredFingerprint, "ETH message PQ fingerprint mismatch");
        require(ethMessageNewEthAddress == newEthAddr, "New ETH address mismatch: PQ message vs ETH message");
        
        // STEP 7: Verify the ETH signature using EIP712 (moved up for proper error ordering)
        bytes32 structHash = storage_s.signatureExtractor.getChangeETHAddressIntentStructHash(newEthAddr, recoveredFingerprint, ethNonce);
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        require(recoveredETHAddress == newEthAddr, "ETH signature must be from new ETH Address");
        
        // STEP 8: State validation - Check if the PQ fingerprint is registered
        address registeredETHAddress = storage_s.epervierKeyToAddress[recoveredFingerprint];
        require(registeredETHAddress != address(0), "PQ fingerprint not registered");
        require(registeredETHAddress == oldEthAddr, "Old ETH Address mismatch: PQ message vs current registration");
        
        // STEP 9: State validation - Check for conflicts
        require(storage_s.changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        require(storage_s.ethAddressToChangeIntentFingerprint[newEthAddr] == address(0), "New ETH Address has pending change intent");
        
        // STEP 9.5: Check if new ETH address is already registered to another PQ key
        address existingPQKey = storage_s.addressToEpervierKey[newEthAddr];
        require(existingPQKey == address(0), "New ETH Address already has registered PQ key");
        
        // STEP 9.6: Check if new ETH address has pending registration intent  
        require(storage_s.pendingIntents[newEthAddr].timestamp == 0, "New ETH Address has pending registration intent");
        
        // STEP 10: Nonce validation
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(storage_s.ethNonces[newEthAddr] == ethNonce, "Invalid ETH nonce");
        
        // STEP 11: Store the intent
        RegistryStorage.ChangeETHAddressIntent memory intent = RegistryStorage.ChangeETHAddressIntent({
            newETHAddress: newEthAddr,
            oldETHAddress: oldEthAddr,
            timestamp: block.timestamp,
            pqNonce: pqNonce
        });
        storage_s.changeETHAddressIntents[recoveredFingerprint] = intent;
        
        // STEP 12: Store the bidirectional mapping
        storage_s.ethAddressToChangeIntentFingerprint[newEthAddr] = recoveredFingerprint;
        
        // STEP 13: Increment nonces
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        storage_s.ethNonces[newEthAddr]++;
        
        emit ChangeETHAddressIntentSubmitted(recoveredFingerprint, newEthAddr, ethNonce);
        
        return (oldEthAddr, newEthAddr, recoveredFingerprint);
    }
    
    function confirmChangeETHAddress(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Validate the ETH change address confirmation message format
        bool valid = storage_s.messageParser.validateETHChangeETHAddressConfirmationMessage(ethMessage);
        require(valid, "Invalid ETH change address confirmation message");
        
        // STEP 2: Parse the ETH change address confirmation message
        (
            address pqFingerprintAddr,
            bytes memory basePQMessage,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            uint256 ethNonce
        ) = storage_s.messageParser.parseETHChangeETHAddressConfirmationMessage(ethMessage);
        
        // STEP 3: Parse the base PQ change address confirmation message
        (address parsedOldEthAddr, address parsedNewEthAddr, uint256 pqNonce) = storage_s.messageParser.parseBasePQChangeETHAddressConfirmMessage(basePQMessage, storage_s.DOMAIN_SEPARATOR);
        
        // STEP 4: Validate the base PQ change address confirmation message format
        require(storage_s.messageParser.validateBasePQChangeETHAddressConfirmMessage(basePQMessage), "Invalid base PQ change address confirmation message");
        
        // STEP 4.5: Verify the embedded PQ signature and cross-validate with claimed fingerprint
        address recoveredPQFingerprint = storage_s.epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        require(recoveredPQFingerprint == pqFingerprintAddr, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // STEP 5: Verify the ETH signature using EIP712
        uint256[32] memory cs1Array;
        uint256[32] memory cs2Array;
        for (uint i = 0; i < 32; i++) {
            cs1Array[i] = cs1[i];
            cs2Array[i] = cs2[i];
        }
        
        bytes32 structHash = storage_s.signatureExtractor.getChangeETHAddressConfirmationStructHash(
            parsedOldEthAddr,
            pqFingerprintAddr,
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
        
        // STEP 5.5: Cross-validate ETH signature address with parsed message content  
        require(recoveredETHAddress == parsedNewEthAddr, "ETH Address mismatch: PQ message vs recovered ETH signature");
        
        // STEP 6: State validation - Check if there's a pending intent
        RegistryStorage.ChangeETHAddressIntent storage intent = storage_s.changeETHAddressIntents[pqFingerprintAddr];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        require(intent.newETHAddress == parsedNewEthAddr, "New ETH address mismatch: intent vs confirmation");
        
        // STEP 7: Get the old ETH address
        address registeredETHAddress = storage_s.epervierKeyToAddress[pqFingerprintAddr];
        require(registeredETHAddress != address(0), "PQ fingerprint not registered");
        require(registeredETHAddress == parsedOldEthAddr, "Old ETH Address mismatch: PQ message vs current registration");
        
        // STEP 8: Nonce validation
        require(storage_s.pqKeyNonces[pqFingerprintAddr] == pqNonce, "Invalid PQ nonce");
        require(storage_s.ethNonces[parsedNewEthAddr] == ethNonce, "Invalid ETH nonce");
        
        // STEP 9: Complete the address change
        storage_s.epervierKeyToAddress[pqFingerprintAddr] = parsedNewEthAddr;
        storage_s.addressToEpervierKey[parsedOldEthAddr] = address(0);
        storage_s.addressToEpervierKey[parsedNewEthAddr] = pqFingerprintAddr;
        
        // STEP 10: Clear the pending intent and bidirectional mapping
        delete storage_s.changeETHAddressIntents[pqFingerprintAddr];
        delete storage_s.ethAddressToChangeIntentFingerprint[parsedNewEthAddr];
        
        // STEP 11: Increment nonces
        storage_s.pqKeyNonces[pqFingerprintAddr]++;
        storage_s.ethNonces[parsedNewEthAddr]++;
        
        emit ChangeETHAddressConfirmed(pqFingerprintAddr, parsedOldEthAddr, parsedNewEthAddr);
        
        return;
    }
    
    function removeChangeETHAddressIntent(
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
        (address intentAddress, ) = storage_s.messageParser.parsePQRemoveChangeIntentMessage(pqMessage, storage_s.DOMAIN_SEPARATOR);
        require(intentAddress != address(0), "Invalid intent address");
        
        // STEP 4: State validation
        address publicKeyAddress = recoveredFingerprint;
        RegistryStorage.ChangeETHAddressIntent storage intent = storage_s.changeETHAddressIntents[intentAddress];
        require(intent.timestamp != 0, "No pending change intent found");
        require(intent.pqNonce == pqNonce, "PQ nonce mismatch");
        
        // STEP 5: Nonce validation
        require(storage_s.pqKeyNonces[publicKeyAddress] == pqNonce, "Invalid PQ nonce");
        
        // STEP 6: Verify the PQ message contains the correct removal text
        require(storage_s.messageParser.validatePQChangeAddressRemovalMessage(pqMessage), "Invalid PQ removal message");
        
        // STEP 7: Clear the intent
        delete storage_s.changeETHAddressIntents[intentAddress];
        delete storage_s.ethAddressToChangeIntentFingerprint[intent.newETHAddress];
        
        // STEP 8: Increment nonce
        storage_s.pqKeyNonces[publicKeyAddress]++;
        
        emit ChangeETHAddressIntentRemoved(publicKeyAddress);
        
        return publicKeyAddress;
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
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        require(storage_s.messageParser.validateETHRemoveChangeIntentMessage(ethMessage), "Invalid ETH remove change intent message");
        (address pqFingerprint, uint256 ethNonce) = storage_s.messageParser.parseETHRemoveChangeIntentMessage(ethMessage);
        bytes32 structHash = storage_s.signatureExtractor.getRemoveChangeIntentStructHash(pqFingerprint, ethNonce);
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        RegistryStorage.ChangeETHAddressIntent storage intent = storage_s.changeETHAddressIntents[pqFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        require(intent.newETHAddress == recoveredETHAddress, "ETH Address not the pending change address for PQ fingerprint");
        require(storage_s.ethAddressToChangeIntentFingerprint[recoveredETHAddress] == pqFingerprint, "ETH Address not registered to PQ fingerprint");
        require(storage_s.changeETHAddressIntents[pqFingerprint].timestamp != 0, "PQ fingerprint does not have pending change intent");
        require(storage_s.ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        delete storage_s.changeETHAddressIntents[pqFingerprint];
        delete storage_s.ethAddressToChangeIntentFingerprint[recoveredETHAddress];
        delete storage_s.ethAddressToChangeIntentFingerprint[storage_s.epervierKeyToAddress[pqFingerprint]];
        storage_s.ethNonces[recoveredETHAddress]++;
        emit ChangeETHAddressIntentRemoved(pqFingerprint);
    }

    /**
     * @dev Remove a pending change ETH Address intent (PQ controlled)
     * @param pqMessage The PQ message containing the remove change intent request
     * @param salt The Epervier signature salt
     * @param cs1 The Epervier signature s1 component
     * @param cs2 The Epervier signature s2 component
     * @param hint The Epervier signature hint
     */
    function removeChangeETHAddressIntentByPQ(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        address recoveredFingerprint = storage_s.epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        require(storage_s.messageParser.validatePQChangeAddressRemovalMessage(pqMessage), "Invalid PQ remove change intent message format");
        (address ethAddress, uint256 pqNonce) = storage_s.messageParser.parsePQRemoveChangeIntentMessage(pqMessage, storage_s.DOMAIN_SEPARATOR);
        RegistryStorage.ChangeETHAddressIntent storage intent = storage_s.changeETHAddressIntents[recoveredFingerprint];
        require(intent.newETHAddress != address(0), "No pending change intent");
        require(intent.timestamp > 0, "No pending change intent");
        require(intent.newETHAddress == ethAddress, "ETH Address not the pending change address for PQ fingerprint");
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        delete storage_s.changeETHAddressIntents[recoveredFingerprint];
        delete storage_s.ethAddressToChangeIntentFingerprint[ethAddress];
        delete storage_s.ethAddressToChangeIntentFingerprint[storage_s.epervierKeyToAddress[recoveredFingerprint]];
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        emit ChangeETHAddressIntentRemoved(recoveredFingerprint);
    }
} 