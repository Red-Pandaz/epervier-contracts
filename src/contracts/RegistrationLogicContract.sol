// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./RegistryStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../interfaces/IPQERC721.sol";
import "forge-std/console.sol";

contract RegistrationLogicContract {
    using ECDSA for bytes32;
    using RegistryStorage for RegistryStorage.Layout;
    
    // Events
    event RegistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationIntentRemoved(address indexed ethAddress);
    
    /**
     * @dev Submit a registration intent using ETH signature
     * @param ethMessage The ETH message containing the registration intent
     * @param v The ETH signature v component
     * @param r The ETH signature r component
     * @param s The ETH signature s component
     * @return ethAddress The ETH address that submitted the intent
     * @return pqFingerprint The PQ fingerprint address recovered from the signature
     */
    function submitRegistrationIntent(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address ethAddress, address pqFingerprint) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        require(storage_s.registeredNFTContractCount > 0, "No NFT contract registered");
        // STEP 1: Validate the ETH registration intent message format
        require(storage_s.messageParser.validateETHRegistrationIntentMessage(ethMessage), "Invalid ETH registration intent message");
        // STEP 2: Parse the ETH registration intent message
        (
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = storage_s.messageParser.parseETHRegistrationIntentMessage(ethMessage);
        // STEP 3: Verify the ETH signature using EIP712
        uint256[32] memory cs1Array;
        uint256[32] memory cs2Array;
        for (uint256 i = 0; i < 32; i++) {
            cs1Array[i] = cs1[i];
            cs2Array[i] = cs2[i];
        }
        bytes32 structHash = storage_s.signatureExtractor.getRegistrationIntentStructHash(
            salt,
            cs1Array,
            cs2Array,
            hint,
            basePQMessage,
            ethNonce
        );
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        // STEP 4: Parse the base PQ message
        (address intentAddress, uint256 pqNonce) = storage_s.messageParser.parseBasePQRegistrationIntentMessage(basePQMessage, storage_s.DOMAIN_SEPARATOR);
        // STEP 5: Validate the base PQ registration intent message format
        require(storage_s.messageParser.validatePQRegistrationIntentMessage(basePQMessage), "Invalid PQ registration intent message");
        // STEP 6: Validate the intent address
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");
        // STEP 7: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        // STEP 8: Cross-reference validation
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");
        // STEP 9: State validation - Check for already registered addresses
        require(storage_s.epervierKeyToAddress[recoveredFingerprint] == address(0), "PQ fingerprint already registered");
        require(storage_s.addressToEpervierKey[recoveredETHAddress] == address(0), "ETH address already registered");
        // STEP 10: State validation - Check for pending intents
        require(storage_s.pendingIntents[recoveredETHAddress].timestamp == 0, "ETH Address has pending registration intent");
        require(storage_s.ethAddressToChangeIntentFingerprint[recoveredETHAddress] == address(0), "ETH Address has pending change intent");
        require(storage_s.unregistrationIntents[recoveredETHAddress].timestamp == 0 && storage_s.ethAddressToUnregistrationFingerprint[recoveredETHAddress] == address(0), "ETH Address has pending unregistration intent");
        require(storage_s.pendingIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(storage_s.changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        require(storage_s.unregistrationIntents[recoveredFingerprint].timestamp == 0 && storage_s.ethAddressToUnregistrationFingerprint[recoveredFingerprint] == address(0), "PQ fingerprint has pending unregistration intent");
        // STEP 11: Nonce validation
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(storage_s.ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        // STEP 12: Store the intent
        storage_s.pendingIntents[intentAddress] = RegistryStorage.Intent({
            pqFingerprint: recoveredFingerprint,
            intentMessage: basePQMessage,
            timestamp: block.timestamp
        });
        // STEP 13: Store the bidirectional mapping
        storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint] = intentAddress;
        // STEP 14: Increment nonces
        storage_s.ethNonces[intentAddress]++;
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        emit RegistrationIntentSubmitted(intentAddress, recoveredFingerprint);
        return (intentAddress, recoveredFingerprint);
    }
    
    /**
     * @dev Confirm a registration using PQ signature
     * @param pqMessage The PQ message containing the registration confirmation
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
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        console.log("DEBUG: require registeredNFTContractCount > 0", storage_s.registeredNFTContractCount);
        require(storage_s.registeredNFTContractCount > 0, "No NFT contract registered");
        console.log("DEBUG: Starting confirmRegistration");
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        console.log("DEBUG: Recovered fingerprint:", recoveredFingerprint);
        console.log("DEBUG: PQ Message length:", pqMessage.length);
        console.log("DEBUG: Salt length:", salt.length);
        console.log("DEBUG: CS1 length:", cs1.length);
        console.log("DEBUG: CS2 length:", cs2.length);
        console.log("DEBUG: Hint:", hint);
        
        // STEP 2: Validate the PQ registration confirmation message format
        bool valid = storage_s.messageParser.validatePQRegistrationConfirmationMessage(pqMessage);
        console.log("DEBUG: require valid PQ registration confirmation message", valid);
        require(valid, "Invalid PQ registration confirmation message");
        console.log("DEBUG: PQ message validation passed");
        
        // STEP 3: Parse the PQ registration confirmation message
        (
            address ethAddress,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s,
            uint256 pqNonce
        ) = storage_s.messageParser.parsePQRegistrationConfirmationMessage(pqMessage, storage_s.DOMAIN_SEPARATOR);
        console.log("DEBUG: Parsed ethAddress:", ethAddress);
        console.log("DEBUG: Parsed pqNonce:", pqNonce);
        
        // STEP 4: Parse the base ETH message to get pqFingerprint and ethNonce
        (address pqFingerprint, uint256 ethNonce) = storage_s.messageParser.parseBaseETHRegistrationConfirmationMessage(baseETHMessage);
        console.log("DEBUG: Parsed pqFingerprint from ETH message:", pqFingerprint);
        console.log("DEBUG: Parsed ethNonce from ETH message:", ethNonce);
        
        // STEP 5: Validate the base ETH registration confirmation message format
        bool baseValid = storage_s.messageParser.validateBaseETHRegistrationConfirmationMessage(baseETHMessage);
        console.log("DEBUG: require valid base ETH registration confirmation message", baseValid);
        require(baseValid, "Invalid base ETH registration confirmation message");
        console.log("DEBUG: Base ETH message validation passed");
        
        // STEP 6: Verify the ETH signature using EIP712
        bytes32 structHash = storage_s.signatureExtractor.getRegistrationConfirmationStructHash(
            pqFingerprint,
            ethNonce
        );
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        console.log("DEBUG: require recoveredETHAddress != 0", recoveredETHAddress);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        console.log("DEBUG: Recovered ETH address:", recoveredETHAddress);
        
        // STEP 7: Cross-reference validation
        console.log("DEBUG: require ethAddress == recoveredETHAddress", ethAddress, recoveredETHAddress);
        require(ethAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        console.log("DEBUG: require pqFingerprint == recoveredFingerprint", pqFingerprint, recoveredFingerprint);
        require(pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        console.log("DEBUG: Cross-reference validation passed");
        
        // STEP 8: State validation - Check PQ fingerprint mapping first
        address intentAddress = storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        console.log("DEBUG: Intent address for fingerprint:", intentAddress);
        console.log("DEBUG: require intentAddress != 0", intentAddress);
        require(intentAddress != address(0), "No pending intent found for PQ fingerprint");
        
        RegistryStorage.Intent storage intent = storage_s.pendingIntents[intentAddress];
        console.log("DEBUG: Intent timestamp:", intent.timestamp);
        console.log("DEBUG: require intent.timestamp != 0", intent.timestamp);
        require(intent.timestamp != 0, "No pending intent found for ETH Address");
        console.log("DEBUG: require intentAddress == recoveredETHAddress", intentAddress, recoveredETHAddress);
        require(intentAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs stored intent");
        console.log("DEBUG: require intent.pqFingerprint == pqFingerprint", intent.pqFingerprint, pqFingerprint);
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        console.log("DEBUG: require intent.pqFingerprint == recoveredFingerprint", intent.pqFingerprint, recoveredFingerprint);
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        console.log("DEBUG: Intent validation passed");
        
        // STEP 9: Comprehensive conflict prevention check
        console.log("DEBUG: require pqFingerprintToPendingIntentAddress[recoveredFingerprint] != 0", storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint]);
        require(storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        console.log("DEBUG: Conflict prevention check passed");
        
        // STEP 10: Nonce validation
        console.log("DEBUG: Expected PQ nonce:", storage_s.pqKeyNonces[recoveredFingerprint]);
        console.log("DEBUG: Provided PQ nonce:", pqNonce);
        console.log("DEBUG: require pqKeyNonces[recoveredFingerprint] == pqNonce", storage_s.pqKeyNonces[recoveredFingerprint], pqNonce);
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        console.log("DEBUG: Expected ETH nonce:", storage_s.ethNonces[ethAddress]);
        console.log("DEBUG: Provided ETH nonce:", ethNonce);
        console.log("DEBUG: require ethNonces[ethAddress] == ethNonce", storage_s.ethNonces[ethAddress], ethNonce);
        require(storage_s.ethNonces[ethAddress] == ethNonce, "Invalid ETH nonce");
        console.log("DEBUG: Nonce validation passed");
        
        // STEP 11: Complete the registration
        // Update bidirectional mappings
        storage_s.epervierKeyToAddress[recoveredFingerprint] = ethAddress;
        storage_s.addressToEpervierKey[ethAddress] = recoveredFingerprint;
        
        // Debug: Log the mapping update
        console.log("Setting addressToEpervierKey[", ethAddress, "] =", recoveredFingerprint);
        console.log("DEBUG: Registration mappings updated");
        
        // STEP 12: Clear the pending intent and bidirectional mapping
        delete storage_s.pendingIntents[ethAddress];
        delete storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        console.log("DEBUG: Pending intent cleared");
        
        // STEP 13: Increment nonces
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        storage_s.ethNonces[ethAddress]++;
        console.log("DEBUG: Nonces incremented");
        
        // STEP 14: Mint NFTs for all registered NFT contracts
        console.log("DEBUG: Starting NFT minting, count:", storage_s.registeredNFTContractAddresses.length);
        for (uint i = 0; i < storage_s.registeredNFTContractAddresses.length; i++) {
            address nftContract = storage_s.registeredNFTContractAddresses[i];
            console.log("DEBUG: Attempting to mint for NFT contract:", nftContract);
            if (storage_s.registeredNFTContracts[nftContract]) {
                try IPQERC721(nftContract).mint(recoveredFingerprint, ethAddress) {
                    console.log("DEBUG: NFT minted successfully for contract:", nftContract);
                } catch {
                    console.log("DEBUG: NFT minting failed for contract:", nftContract);
                    // NFT minting failed, but don't revert the registration
                }
            }
        }
        console.log("DEBUG: Registration confirmation completed successfully");
        emit RegistrationConfirmed(ethAddress, recoveredFingerprint);
    }

    /**
     * @dev Debug function to check storage slot and mapping value
     */
    function debugCheckMapping(address ethAddress) external view returns (address, bytes32) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        return (storage_s.addressToEpervierKey[ethAddress], RegistryStorage.getStorageSlot());
    }
    
    /**
     * @dev Remove a pending registration intent (ETH controlled)
     * @param ethMessage The ETH message containing the remove intent request
     * @param v The ETH signature v component
     * @param r The ETH signature r component  
     * @param s The ETH signature s component
     */
    function removeRegistrationIntentByETH(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Validate the ETH remove registration intent message format
        require(storage_s.messageParser.validateETHRemoveRegistrationIntentMessage(ethMessage), "Invalid ETH remove registration intent message");
        
        // STEP 2: Parse the ETH remove intent message
        (address pqFingerprint, uint256 ethNonce) = storage_s.messageParser.parseETHRemoveRegistrationIntentMessage(ethMessage);
        
        // STEP 3: Verify the ETH signature using EIP712
        bytes32 structHash = storage_s.signatureExtractor.getRemoveIntentStructHash(
            pqFingerprint,
            ethNonce
        );
        bytes32 digest = storage_s.signatureExtractor.getEIP712Digest(storage_s.DOMAIN_SEPARATOR, structHash);
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 4: State validation
        RegistryStorage.Intent storage intent = storage_s.pendingIntents[recoveredETHAddress];
        require(intent.timestamp != 0, "No pending intent found for recovered ETH Address");
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        require(storage_s.pqFingerprintToPendingIntentAddress[pqFingerprint] == recoveredETHAddress, "Bidirectional mapping mismatch");
        
        // STEP 5: Comprehensive conflict prevention check
        require(storage_s.pendingIntents[recoveredETHAddress].timestamp != 0, "ETH Address does not have pending registration intent");
        require(storage_s.pqFingerprintToPendingIntentAddress[pqFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 6: Nonce validation
        require(storage_s.ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 7: Store the PQ fingerprint before clearing the intent
        address pqFingerprintToClear = intent.pqFingerprint;
        
        // STEP 8: Clear the intent
        delete storage_s.pendingIntents[recoveredETHAddress];
        delete storage_s.pqFingerprintToPendingIntentAddress[pqFingerprintToClear];
        
        // STEP 9: Increment nonce
        storage_s.ethNonces[recoveredETHAddress]++;
        
        emit RegistrationIntentRemoved(recoveredETHAddress);
    }
    
    /**
     * @dev Remove a pending registration intent (PQ controlled)
     * @param pqMessage The PQ message containing the remove intent request
     * @param salt The Epervier signature salt (40 bytes)
     * @param cs1 The Epervier signature s1 component (32 uint256 array)
     * @param cs2 The Epervier signature s2 component (32 uint256 array)
     * @param hint The Epervier signature hint
     */
    function removeRegistrationIntentByPQ(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = storage_s.epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Extract PQ nonce from the PQ message
        uint256 pqNonce = storage_s.messageParser.extractPQNonceFromRemoveMessage(pqMessage);
        
        // STEP 3: State validation
        address intentAddress = storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        require(intentAddress != address(0), "No pending intent found for this PQ fingerprint");
        
        RegistryStorage.Intent storage intent = storage_s.pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for referenced ETH Address");
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        require(storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint] == intentAddress, "Bidirectional mapping mismatch");
        
        // STEP 4: Comprehensive conflict prevention check
        require(storage_s.pendingIntents[intentAddress].timestamp != 0, "ETH Address does not have pending registration intent");
        require(storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 5: Nonce validation
        require(storage_s.pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // STEP 6: Validate domain separator in PQ message
        require(storage_s.messageParser.validateDomainSeparator(pqMessage, storage_s.DOMAIN_SEPARATOR), "Invalid domain separator in PQ message");
        
        // STEP 7: Verify the PQ message contains the correct removal text
        require(storage_s.messageParser.validatePQRemoveIntentMessage(pqMessage), "Invalid PQ removal message");
        
        // STEP 8: Clear both mappings
        delete storage_s.pendingIntents[intentAddress];
        delete storage_s.pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // STEP 9: Increment nonce
        storage_s.pqKeyNonces[recoveredFingerprint]++;
        
        emit RegistrationIntentRemoved(intentAddress);
    }
    
    // Temporary debug getter - remove after fixing
    function debugGetAddressToEpervierKey(address ethAddress) external view returns (address) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        return storage_s.addressToEpervierKey[ethAddress];
    }
} 