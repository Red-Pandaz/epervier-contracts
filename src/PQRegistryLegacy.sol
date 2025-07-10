// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./libraries/MessageParser.sol";
import "./libraries/MessageValidation.sol";
import "./libraries/SignatureExtractor.sol";
import "./libraries/AddressUtils.sol";
import "./interfaces/IEpervierVerifier.sol";
import "./interfaces/IPQERC721.sol";


contract PQRegistryLegacy {
    using ECDSA for bytes32;
    using Strings for string;
    
    // --- State variables and structs needed by the main functions ---
    struct Intent {
        address pqFingerprint;
        bytes intentMessage;
        uint256 timestamp;
    }
    mapping(address => Intent) public pendingIntents;
    mapping(address => address) public addressToEpervierKey;
    mapping(address => address) public epervierKeyToAddress;
    mapping(address => uint256) public ethNonces;
    mapping(address => uint256) public pqKeyNonces;
    mapping(address => address) public pqFingerprintToPendingIntentAddress;
    mapping(address => ChangeETHAddressIntent) public changeETHAddressIntents;
    mapping(address => UnregistrationIntent) public unregistrationIntents;
    
    // --- Reverse Mappings for Conflict Prevention ---
    // Map ETH address to PQ fingerprint for change intents (reverse of changeETHAddressIntents)
    mapping(address => address) public ethAddressToChangeIntentFingerprint;
    // Map ETH address to PQ fingerprint for unregistration intents (reverse of unregistrationIntents)
    mapping(address => address) public ethAddressToUnregistrationFingerprint;
    
    // Fixed struct definition to match the original
    struct ChangeETHAddressIntent { 
        address newETHAddress;
        bytes pqMessage;
        uint256 timestamp;
        uint256 pqNonce;
    }
    
    struct UnregistrationIntent { 
        uint256 timestamp; 
        uint256[2] publicKey; 
        address publicKeyAddress; 
        bytes pqMessage; 
    }
    
    // --- Events ---
    event RegistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event RegistrationIntentRemoved(address indexed ethAddress);
    event ChangeETHAddressIntentSubmitted(address indexed pqFingerprint, address indexed newETHAddress, uint256 indexed ethNonce);
    event ChangeETHAddressConfirmed(address indexed pqFingerprint, address indexed oldETHAddress, address indexed newETHAddress);
    event ChangeETHAddressIntentRemoved(address indexed pqFingerprint);
    event UnregistrationIntentSubmitted(address indexed ethAddress, address indexed pqFingerprint);
    event UnregistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    event UnregistrationIntentRemoved(address indexed pqFingerprint);
    
    // Debug events
    event DebugParsedIntentAddress(address parsedAddress);
    event DebugParseStep(string step, uint256 value);
    event DebugEthMessageHex(bytes ethMessage);
    event DebugAddress(string label, address addr);
    
    // --- External dependencies (mocked as interfaces for this extraction) ---
    IEpervierVerifier public epervierVerifier;
    
    // NFT contract tracking
    mapping(address => bool) public registeredNFTContracts;
    address[] public registeredNFTContractAddresses;
    uint256 public registeredNFTContractCount;
    
    // Event for NFT minting
    event NFTMinted(address indexed nftContract, address indexed pqFingerprint, address indexed ethAddress, uint256 tokenId);
    
    // EIP-712 Domain Separator - Hardcoded for consistency with test vectors
    string public constant DOMAIN_NAME = "PQRegistry";
    string public constant DOMAIN_VERSION = "1";
    bytes32 public constant DOMAIN_SEPARATOR = 0x07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92;
    
    // EIP-712 bytes32 public constant REGISTRATION_INTENT_TYPE_HASH = keccak256("RegistrationIntent(uint256 ethNonce,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage)");
    bytes32 public constant REGISTRATION_CONFIRMATION_TYPE_HASH = keccak256("RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant REMOVE_INTENT_TYPE_HASH = keccak256("RemoveIntent(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH = keccak256("ChangeETHAddressIntent(address newETHAddress,address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH = keccak256("ChangeETHAddressConfirmation(address oldETHAddress,address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant UNREGISTRATION_INTENT_TYPE_HASH = keccak256("UnregistrationIntent(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant UNREGISTRATION_CONFIRMATION_TYPE_HASH = keccak256("UnregistrationConfirmation(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant REMOVE_CHANGE_INTENT_TYPE_HASH = keccak256("RemoveChangeIntent(address pqFingerprint,uint256 ethNonce)");
    bytes32 public constant REMOVE_UNREGISTRATION_INTENT_TYPE_HASH = keccak256("RemoveUnregistrationIntent(uint256 ethNonce)");
    
    
    constructor(
        address _epervierVerifier
    ) {
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        
        epervierVerifier = IEpervierVerifier(_epervierVerifier);
    }
    
    /**
     * @dev Initialize the registry with NFT contracts
     * This can be called after deployment to register NFT contracts
     * @param nftContracts Array of NFT contract addresses to register
     */
    function initializeNFTContracts(address[] memory nftContracts) external {
        for (uint256 i = 0; i < nftContracts.length; i++) {
            require(nftContracts[i] != address(0), "Invalid NFT contract address");
            registeredNFTContracts[nftContracts[i]] = true;
            registeredNFTContractAddresses.push(nftContracts[i]);
            registeredNFTContractCount++;
        }
    }
    
    /**
     * @dev Returns the EIP-712 domain separator
     */
    function getDomainSeparator() external view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }
    
    // --- Main functions ---
    function submitRegistrationIntent(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(registeredNFTContractCount > 0, "No NFT contract registered");
        
        // STEP 1: Validate the ETH registration intent message format
        require(MessageParser.validateETHRegistrationIntentMessage(ethMessage), "Invalid ETH registration intent message");
        
        // STEP 2: Parse the ETH registration intent message
        (
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = MessageParser.parseETHRegistrationIntentMessage(ethMessage);
        
        // STEP 3: Verify the ETH signature using EIP712
        // Convert uint256[] to uint256[32] for the struct hash
        uint256[32] memory cs1Array;
        uint256[32] memory cs2Array;
        for (uint256 i = 0; i < 32; i++) {
            cs1Array[i] = cs1[i];
            cs2Array[i] = cs2[i];
        }
        
        bytes32 structHash = SignatureExtractor.getRegistrationIntentStructHash(
            salt,
            cs1Array,
            cs2Array,
            hint,
            basePQMessage,
            ethNonce
        );
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        // DEBUG: Show the digest being used for ecrecover
        console.log("DEBUG: Digest for ecrecover:", uint256(digest));
        console.log("DEBUG: v value:", v);
        console.log("DEBUG: r value:", uint256(r));
        console.log("DEBUG: s value:", uint256(s));
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        console.log("DEBUG: Digest for ecrecover:", uint256(digest));
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 4: Parse the base PQ message
        (address intentAddress, uint256 pqNonce) = MessageParser.parseBasePQRegistrationIntentMessage(basePQMessage, DOMAIN_SEPARATOR);
        
        // STEP 5: Validate the base PQ registration intent message format
        require(MessageParser.validatePQRegistrationIntentMessage(basePQMessage), "Invalid PQ registration intent message");
        
        // Debug logging for address comparison
        emit DebugParseStep("recovered_eth_address", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address", uint256(uint160(intentAddress)));
        emit DebugParseStep("addresses_equal", uint256(uint160(recoveredETHAddress == intentAddress ? 1 : 0)));
        
        // Add console logs for debugging
        emit DebugAddress("recovered_eth_address", recoveredETHAddress);
        emit DebugAddress("parsed_intent_address", intentAddress);
        
        // STEP 6: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        
        // STEP 7: Cross-reference validation
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");
        
        // STEP 8: State validation - Check for already registered addresses
        require(epervierKeyToAddress[recoveredFingerprint] == address(0), "PQ fingerprint already registered");
        require(addressToEpervierKey[recoveredETHAddress] == address(0), "ETH address already registered");
        
        // STEP 9: State validation - Check for pending intents
        require(pendingIntents[recoveredETHAddress].timestamp == 0, "ETH Address has pending registration intent");
        require(ethAddressToChangeIntentFingerprint[recoveredETHAddress] == address(0), "ETH Address has pending change intent");
        require(unregistrationIntents[recoveredETHAddress].timestamp == 0 && ethAddressToUnregistrationFingerprint[recoveredETHAddress] == address(0), "ETH Address has pending unregistration intent");
        require(pendingIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        require(unregistrationIntents[recoveredFingerprint].timestamp == 0 && ethAddressToUnregistrationFingerprint[recoveredFingerprint] == address(0), "PQ fingerprint has pending unregistration intent");
        
        // STEP 10: Nonce validation
        
        // Debug logging for nonce comparison
        console.log("DEBUG: PQ nonce validation - recoveredFingerprint:", uint256(uint160(recoveredFingerprint)));
        console.log("DEBUG: PQ nonce validation - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        console.log("DEBUG: PQ nonce validation - pqNonce from message:", pqNonce);
        console.log("DEBUG: PQ nonce validation - nonces match:", pqKeyNonces[recoveredFingerprint] == pqNonce);
        
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 11: Store the intent
        pendingIntents[intentAddress] = Intent({
            pqFingerprint: recoveredFingerprint,
            intentMessage: basePQMessage,
            timestamp: block.timestamp
        });
        
        // STEP 12: Store the bidirectional mapping
        pqFingerprintToPendingIntentAddress[recoveredFingerprint] = intentAddress;
        
        // STEP 13: Increment nonces
        ethNonces[intentAddress]++;
        pqKeyNonces[recoveredFingerprint]++;
        
        
        emit RegistrationIntentSubmitted(intentAddress, recoveredFingerprint);
    }

    function confirmRegistration(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        require(registeredNFTContractCount > 0, "No NFT contract registered");
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ registration confirmation message format
        console.log("DEBUG: pqMessage length:", pqMessage.length);
        console.log("DEBUG: pqMessage first 64 bytes:");
        for (uint i = 0; i < 64 && i < pqMessage.length; i++) {
            console.log("  pqMessage[", i, "]:", uint8(pqMessage[i]));
        }
        bool valid = MessageParser.validatePQRegistrationConfirmationMessage(pqMessage);
        console.log("DEBUG: validatePQRegistrationConfirmationMessage result:", valid);
        require(valid, "Invalid PQ registration confirmation message");
        
        // STEP 3: Parse the PQ registration confirmation message
        (
            address ethAddress,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s,
            uint256 pqNonce
        ) = MessageParser.parsePQRegistrationConfirmationMessage(pqMessage, DOMAIN_SEPARATOR);
        
        // STEP 4: Parse the base ETH message to get pqFingerprint and ethNonce
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseBaseETHRegistrationConfirmationMessage(baseETHMessage);
        
        // STEP 5: Validate the base ETH registration confirmation message format
        require(MessageParser.validateBaseETHRegistrationConfirmationMessage(baseETHMessage), "Invalid base ETH registration confirmation message");
        
        // STEP 6: Verify the ETH signature using EIP712
        bytes32 structHash = SignatureExtractor.getRegistrationConfirmationStructHash(
            pqFingerprint,
            ethNonce
        );
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        // DEBUG: Show the digest being used for ecrecover
        console.log("DEBUG: Digest for ecrecover:", uint256(digest));
        console.log("DEBUG: v value:", v);
        console.log("DEBUG: r value:", uint256(r));
        console.log("DEBUG: s value:", uint256(s));
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        console.log("DEBUG: Digest for ecrecover:", uint256(digest));
        require(recoveredETHAddress != address(0), "Invalid ETH signature");

        // STEP 7: Cross-reference validation
        require(ethAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        require(pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // STEP 8: State validation - Check PQ fingerprint mapping first
        address intentAddress = pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        require(intentAddress != address(0), "No pending intent found for PQ fingerprint");
        
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for ETH Address");
        require(intentAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs stored intent");
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        
        // STEP 9: Comprehensive conflict prevention check
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 10: Nonce validation
        
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[ethAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 11: Complete the registration
        epervierKeyToAddress[recoveredFingerprint] = ethAddress;
        addressToEpervierKey[ethAddress] = recoveredFingerprint;
        
        // STEP 12: Clear the pending intent and bidirectional mapping
        delete pendingIntents[ethAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // STEP 13: Increment nonces
        pqKeyNonces[recoveredFingerprint]++;
        ethNonces[ethAddress]++;
        
        // STEP 14: Mint NFTs for all registered NFT contracts
        for (uint i = 0; i < registeredNFTContractAddresses.length; i++) {
            address nftContract = registeredNFTContractAddresses[i];
            if (registeredNFTContracts[nftContract]) {
                try IPQERC721(nftContract).mint(recoveredFingerprint, ethAddress) {
                    // NFT minted successfully
                } catch {
                    // NFT minting failed, but don't revert the registration
                    console.log("Failed to mint NFT for contract:", nftContract);
                }
            }
        }
        
        emit RegistrationConfirmed(ethAddress, recoveredFingerprint);
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
        // STEP 1: Validate the ETH remove registration intent message format
        require(MessageParser.validateETHRemoveRegistrationIntentMessage(ethMessage), "Invalid ETH remove registration intent message");
        
        // STEP 2: Parse the ETH remove intent message
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseETHRemoveRegistrationIntentMessage(ethMessage);
        
        // STEP 3: Verify the ETH signature using EIP712
        bytes32 structHash = SignatureExtractor.getRemoveIntentStructHash(
            pqFingerprint,
            ethNonce
        );
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        console.log("Contract struct hash:", uint256(structHash));
        console.log("Contract digest:", uint256(digest));
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 4: State validation
        Intent storage intent = pendingIntents[recoveredETHAddress];
        require(intent.timestamp != 0, "No pending intent found for recovered ETH Address");
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        require(pqFingerprintToPendingIntentAddress[pqFingerprint] == recoveredETHAddress, "Bidirectional mapping mismatch");
        
        // STEP 5: Comprehensive conflict prevention check
        require(pendingIntents[recoveredETHAddress].timestamp != 0, "ETH Address does not have pending registration intent");
        require(pqFingerprintToPendingIntentAddress[pqFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 6: Nonce validation
        require(ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 7: Store the PQ fingerprint before clearing the intent
        address pqFingerprintToClear = intent.pqFingerprint;
        
        // STEP 8: Clear the intent
        delete pendingIntents[recoveredETHAddress];
        delete pqFingerprintToPendingIntentAddress[pqFingerprintToClear];
        
        // STEP 9: Increment nonce
        ethNonces[recoveredETHAddress]++;
        
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
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Extract PQ nonce from the PQ message
        uint256 pqNonce = MessageParser.extractPQNonceFromRemoveMessage(pqMessage);
        
        // STEP 3: State validation
        address intentAddress = pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        require(intentAddress != address(0), "No pending intent found for this PQ fingerprint");
        console.log("DEBUG: intentAddress:", intentAddress);
        
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for referenced ETH Address");
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] == intentAddress, "Bidirectional mapping mismatch");
        
        // STEP 4: Comprehensive conflict prevention check
        require(pendingIntents[intentAddress].timestamp != 0, "ETH Address does not have pending registration intent");
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 5: Nonce validation
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // STEP 6: Validate domain separator in PQ message
        require(MessageParser.validateDomainSeparator(pqMessage, DOMAIN_SEPARATOR), "Invalid domain separator in PQ message");
        
        // STEP 7: Verify the PQ message contains the correct removal text
        require(MessageParser.validatePQRemoveIntentMessage(pqMessage), "Invalid PQ removal message");
        
        // STEP 8: Clear both mappings
        delete pendingIntents[intentAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // STEP 9: Increment nonce
        pqKeyNonces[recoveredFingerprint]++;
        
        emit RegistrationIntentRemoved(intentAddress);
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
        // STEP 1: Validate the ETH remove change intent message format
        require(MessageParser.validateETHRemoveChangeIntentMessage(ethMessage), "Invalid ETH remove change intent message");
        
        // STEP 2: Parse the ETH remove change intent message
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseETHRemoveChangeIntentMessage(ethMessage);
        
        // STEP 3: Verify the ETH signature using EIP712
        bytes32 structHash = SignatureExtractor.getRemoveChangeIntentStructHash(pqFingerprint, ethNonce);
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        // DEBUG: Print the type hash for comparison
        console.log("DEBUG: Solidity REMOVE_CHANGE_INTENT_TYPE_HASH:", uint256(SignatureExtractor.REMOVE_CHANGE_INTENT_TYPE_HASH));
        
        // DEBUG: Print the values for comparison with Python
        console.log("DEBUG: removeChangeETHAddressIntentByETH - structHash:", uint256(structHash));
        console.log("DEBUG: removeChangeETHAddressIntentByETH - digest:", uint256(digest));
        console.log("DEBUG: removeChangeETHAddressIntentByETH - digest (hex): 0x", uint256(digest));
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");

        // COMPREHENSIVE ADDRESS LOGGING
        console.log("DEBUG: Recovered ETH address:", uint256(uint160(recoveredETHAddress)));
        console.log("DEBUG: Recovered ETH address (hex): 0x", uint256(uint160(recoveredETHAddress)));
        console.log("DEBUG: Parsed pqFingerprint:", uint256(uint160(pqFingerprint)));
        console.log("DEBUG: Parsed pqFingerprint (hex): 0x", uint256(uint160(pqFingerprint)));

        // STEP 4: State validation
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[pqFingerprint];
        console.log("DEBUG: Intent timestamp:", intent.timestamp);
        console.log("DEBUG: Intent newETHAddress:", uint256(uint160(intent.newETHAddress)));
        console.log("DEBUG: Intent newETHAddress (hex): 0x", uint256(uint160(intent.newETHAddress)));
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        
        // COMPREHENSIVE MAPPING LOGGING
        address mappedETHAddress = epervierKeyToAddress[pqFingerprint];
        address oldETHAddress = epervierKeyToAddress[pqFingerprint];
        address newETHAddress = intent.newETHAddress;
        
        console.log("DEBUG: PQ fingerprint:", uint256(uint160(pqFingerprint)));
        console.log("DEBUG: PQ fingerprint (hex): 0x", uint256(uint160(pqFingerprint)));
        console.log("DEBUG: Mapped ETH address (old):", uint256(uint160(mappedETHAddress)));
        console.log("DEBUG: Mapped ETH address (old) (hex): 0x", uint256(uint160(mappedETHAddress)));
        console.log("DEBUG: New ETH address from intent:", uint256(uint160(newETHAddress)));
        console.log("DEBUG: New ETH address from intent (hex): 0x", uint256(uint160(newETHAddress)));
        console.log("DEBUG: Recovered ETH address:", uint256(uint160(recoveredETHAddress)));
        console.log("DEBUG: Recovered ETH address (hex): 0x", uint256(uint160(recoveredETHAddress)));
        console.log("DEBUG: ethAddressToChangeIntentFingerprint[recoveredETHAddress]:", uint256(uint160(ethAddressToChangeIntentFingerprint[recoveredETHAddress])));
        console.log("DEBUG: ethAddressToChangeIntentFingerprint[recoveredETHAddress] (hex): 0x", uint256(uint160(ethAddressToChangeIntentFingerprint[recoveredETHAddress])));
        
        // Check all possible mappings
        console.log("DEBUG: addressToEpervierKey[recoveredETHAddress]:", uint256(uint160(addressToEpervierKey[recoveredETHAddress])));
        console.log("DEBUG: addressToEpervierKey[recoveredETHAddress] (hex): 0x", uint256(uint160(addressToEpervierKey[recoveredETHAddress])));
        console.log("DEBUG: epervierKeyToAddress[recoveredETHAddress]:", uint256(uint160(epervierKeyToAddress[recoveredETHAddress])));
        console.log("DEBUG: epervierKeyToAddress[recoveredETHAddress] (hex): 0x", uint256(uint160(epervierKeyToAddress[recoveredETHAddress])));
        
        require(intent.newETHAddress == recoveredETHAddress, "ETH Address not the pending change address for PQ fingerprint");
        require(ethAddressToChangeIntentFingerprint[recoveredETHAddress] == pqFingerprint, "ETH Address not registered to PQ fingerprint");
        
        // STEP 5: Comprehensive conflict prevention check
        require(changeETHAddressIntents[pqFingerprint].timestamp != 0, "PQ fingerprint does not have pending change intent");
        
        // STEP 6: Nonce validation
        require(ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 7: Clear the intent
        delete changeETHAddressIntents[pqFingerprint];
        delete ethAddressToChangeIntentFingerprint[recoveredETHAddress];
        delete ethAddressToChangeIntentFingerprint[epervierKeyToAddress[pqFingerprint]];
        
        // STEP 8: Increment nonce
        ethNonces[recoveredETHAddress]++;
        
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
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ remove change intent message format
        require(MessageParser.validatePQChangeAddressRemovalMessage(pqMessage), "Invalid PQ remove change intent message format");
        
        // STEP 3: Parse the PQ remove change intent message
        // Format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
        (address ethAddress, uint256 pqNonce) = MessageParser.parsePQRemoveChangeIntentMessage(pqMessage, DOMAIN_SEPARATOR);
        
        // STEP 4: State validation
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[recoveredFingerprint];
        
        // DEBUG: Print all relevant addresses and fingerprints
        console.log("DEBUG: removeChangeETHAddressIntentByPQ - recoveredFingerprint:", uint256(uint160(recoveredFingerprint)));
        console.log("DEBUG: removeChangeETHAddressIntentByPQ - ethAddress from message:", uint256(uint160(ethAddress)));
        console.log("DEBUG: removeChangeETHAddressIntentByPQ - intent.newETHAddress:", uint256(uint160(intent.newETHAddress)));
        console.log("DEBUG: removeChangeETHAddressIntentByPQ - intent.timestamp:", intent.timestamp);
        console.log("DEBUG: removeChangeETHAddressIntentByPQ - addresses match:", intent.newETHAddress == ethAddress);
        
        
        // STEP 5: Verify there's a pending change intent
        console.log("New ETH Address:", intent.newETHAddress);
        console.log("ETH Address from message:", ethAddress);
        require(intent.newETHAddress != address(0), "No pending change intent");
        require(intent.timestamp > 0, "No pending change intent");
        require(intent.newETHAddress == ethAddress, "ETH Address not the pending change address for PQ fingerprint");
        
        // STEP 6: Nonce validation
        // DEBUG: Print PQ nonce in message and contract
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // STEP 7: Clear the intent
        delete changeETHAddressIntents[recoveredFingerprint];
        delete ethAddressToChangeIntentFingerprint[ethAddress];
        delete ethAddressToChangeIntentFingerprint[epervierKeyToAddress[recoveredFingerprint]];
        
        // STEP 8: Increment nonce
        pqKeyNonces[recoveredFingerprint]++;
        
        emit ChangeETHAddressIntentRemoved(recoveredFingerprint);
    }

    function submitChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ change address intent message format
        require(MessageParser.validatePQChangeETHAddressIntentMessage(pqMessage), "Invalid PQ change address intent message");
        
        // STEP 3: Parse the PQ change address intent message
        (address oldEthAddress, address newEthAddress, uint256 pqNonce, bytes memory baseETHMessage, uint8 v, bytes32 r, bytes32 s) = MessageParser.parsePQChangeETHAddressIntentMessage(pqMessage, DOMAIN_SEPARATOR);
        
        // STEP 4: Parse the base ETH message
        (address ethMessagePqFingerprint, address ethMessageNewEthAddress, uint256 ethNonce) = MessageParser.parseBaseETHChangeETHAddressIntentMessage(baseETHMessage);
        
        // STEP 5: Validate the base ETH change address intent message format
        require(MessageParser.validateBaseETHChangeETHAddressIntentMessage(baseETHMessage), "Invalid base ETH change address intent message");
        
        // STEP 6: Verify the ETH signature using EIP712
        bytes32 structHash = SignatureExtractor.getChangeETHAddressIntentStructHash(
            ethMessageNewEthAddress,
            ethMessagePqFingerprint,
            ethNonce
        );
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        // DEBUG: Print the values for comparison with Python
        console.log("DEBUG: submitChangeETHAddressIntent - structHash:", uint256(structHash));
        console.log("DEBUG: submitChangeETHAddressIntent - digest:", uint256(digest));
        console.log("DEBUG: submitChangeETHAddressIntent - digest (hex): 0x", uint256(digest));
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        console.log("DEBUG: submitChangeETHAddressIntent - recoveredETHAddress:", uint256(uint160(recoveredETHAddress)));
        console.log("DEBUG: submitChangeETHAddressIntent - newEthAddress:", uint256(uint160(newEthAddress)));
        console.log("DEBUG: submitChangeETHAddressIntent - addresses match:", recoveredETHAddress == newEthAddress);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 7: Cross-reference validation
        require(newEthAddress == recoveredETHAddress, "ETH signature must be from new ETH Address");
        require(ethMessagePqFingerprint == recoveredFingerprint, "ETH message PQ fingerprint mismatch");
        require(ethMessageNewEthAddress == newEthAddress, "ETH message new ETH Address mismatch");
        
        // STEP 8: State validation
        address currentETHAddress = epervierKeyToAddress[recoveredFingerprint];
        require(currentETHAddress != address(0), "PQ fingerprint not registered");
        require(oldEthAddress == currentETHAddress, "Old ETH Address mismatch: PQ message vs current registration");
        require(addressToEpervierKey[currentETHAddress] == recoveredFingerprint, "PQ key not registered to current address");
        require(newEthAddress != currentETHAddress, "New ETH Address must be different from current address");
        require(addressToEpervierKey[newEthAddress] == address(0), "New ETH Address already has registered PQ key");
        
        // STEP 9: Conflict prevention
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        require(ethAddressToChangeIntentFingerprint[oldEthAddress] == address(0), "Old ETH Address has pending change intent");
        require(ethAddressToChangeIntentFingerprint[newEthAddress] == address(0), "New ETH Address has pending change intent");
        require(pendingIntents[newEthAddress].timestamp == 0, "New ETH Address has pending registration intent");
        
        // STEP 10: Nonce validation
        console.log("DEBUG: submitChangeETHAddressIntent - Nonce validation:");
        console.log("  - pqKeyNonces[recoveredFingerprint] (contract):", pqKeyNonces[recoveredFingerprint]);
        console.log("  - pqNonce from message:", pqNonce);
        console.log("  - ethNonces[newEthAddress] (contract):", ethNonces[newEthAddress]);
        console.log("  - ethNonce from message:", ethNonce);
        
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[newEthAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 11: Store the change intent
        changeETHAddressIntents[recoveredFingerprint] = ChangeETHAddressIntent({
            newETHAddress: newEthAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp,
            pqNonce: pqKeyNonces[recoveredFingerprint]
        });
        ethAddressToChangeIntentFingerprint[oldEthAddress] = recoveredFingerprint;
        ethAddressToChangeIntentFingerprint[newEthAddress] = recoveredFingerprint;
        
        // STEP 12: Increment nonces
        console.log("DEBUG: submitChangeETHAddressIntent - Before nonce increments:");
        console.log("  - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        console.log("  - ethNonces[newEthAddress]:", ethNonces[newEthAddress]);
        
        pqKeyNonces[recoveredFingerprint]++;
        ethNonces[newEthAddress]++;
        
        console.log("DEBUG: submitChangeETHAddressIntent - After nonce increments:");
        console.log("  - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        console.log("  - ethNonces[newEthAddress]:", ethNonces[newEthAddress]);

        emit ChangeETHAddressIntentSubmitted(recoveredFingerprint, newEthAddress, ethNonce);

        // DEBUG: Log mappings after creating the intent
        console.log("DEBUG: After intent creation - ethAddressToChangeIntentFingerprint[newEthAddress]:", uint256(uint160(ethAddressToChangeIntentFingerprint[newEthAddress])));
        console.log("DEBUG: After intent creation - newEthAddress:", uint256(uint160(newEthAddress)));
        console.log("DEBUG: After intent creation - recoveredFingerprint:", uint256(uint160(recoveredFingerprint)));
    }
    
    function confirmChangeETHAddress(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // STEP 1: Validate the ETH change address confirmation message format
        bool valid = MessageParser.validateETHChangeETHAddressConfirmationMessage(ethMessage);
        require(valid, "Invalid ETH change address confirmation message");
        
        // STEP 2: Parse the ETH change address confirmation message
        (
            address pqFingerprint,
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = MessageParser.parseETHChangeETHAddressConfirmationMessage(ethMessage);
        
        // STEP 2: Parse the base PQ change address confirmation message
        (address oldEthAddress, address newEthAddress, uint256 pqNonce) = MessageParser.parseBasePQChangeETHAddressConfirmMessage(basePQMessage, DOMAIN_SEPARATOR);
        
        // STEP 3: Validate the base PQ change address confirmation message format
        require(MessageParser.validateBasePQChangeETHAddressConfirmMessage(basePQMessage), "Invalid base PQ change address confirmation message");
        
        // STEP 4: Verify the ETH signature using EIP712 (use old ETH address from PQ message)
        // Convert cs1 and cs2 to fixed-size arrays for EIP-712 struct hash
        uint256[32] memory cs1_fixed;
        uint256[32] memory cs2_fixed;
        for (uint i = 0; i < 32; i++) {
            cs1_fixed[i] = cs1[i];
            cs2_fixed[i] = cs2[i];
        }
        bytes32 structHash = SignatureExtractor.getChangeETHAddressConfirmationStructHash(
            oldEthAddress,
            pqFingerprint,
            basePQMessage,
            salt,
            cs1_fixed,
            cs2_fixed,
            hint,
            ethNonce
        );
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        // DEBUG: Print the values for comparison with Python
        console.log("DEBUG: Contract oldEthAddress:", oldEthAddress);
        console.log("DEBUG: Contract ethNonce:", ethNonce);
        console.log("DEBUG: Contract structHash (bytes32):");
        console.logBytes32(structHash);
        console.log("DEBUG: Contract digest (bytes32):");
        console.logBytes32(digest);
        console.log("DEBUG: Contract digest (uint256):", uint256(digest));
        console.log("DEBUG: Contract digest (hex): 0x", uint256(digest));
        
        // DEBUG: Print the packed bytes that are being hashed
        bytes memory packed = abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash);
        console.log("DEBUG: Contract packed bytes:");
        console.logBytes(packed);
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        console.log("DEBUG: Contract recoveredETHAddress:", uint256(uint160(recoveredETHAddress)));
        console.log("DEBUG: Contract newEthAddress:", uint256(uint160(newEthAddress)));
        console.log("DEBUG: Contract addresses match:", recoveredETHAddress == newEthAddress);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 4: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        
        // STEP 5: Cross-reference validation
        require(pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        require(newEthAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        
        // STEP 6: State validation
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        require(intent.newETHAddress == newEthAddress, "ETH Address mismatch: PQ message vs stored intent");
        require(addressToEpervierKey[oldEthAddress] == recoveredFingerprint, "Old ETH Address mismatch: PQ message vs current registration");
        require(epervierKeyToAddress[recoveredFingerprint] == oldEthAddress, "PQ fingerprint not registered to old ETH Address");

        // STEP 7: Nonce validation
        
        // Debug logging for nonce comparison
        console.log("DEBUG: PQ nonce validation - recoveredFingerprint:", uint256(uint160(recoveredFingerprint)));
        console.log("DEBUG: PQ nonce validation - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        console.log("DEBUG: PQ nonce validation - pqNonce from message:", pqNonce);
        console.log("DEBUG: PQ nonce validation - nonces match:", pqKeyNonces[recoveredFingerprint] == pqNonce);
        
        // ETH nonce validation with detailed logging
        console.log("DEBUG: ETH nonce validation - newEthAddress:", uint256(uint160(newEthAddress)));
        console.log("DEBUG: ETH nonce validation - ethNonces[newEthAddress] (contract state):", ethNonces[newEthAddress]);
        console.log("DEBUG: ETH nonce validation - ethNonce from message:", ethNonce);
        console.log("DEBUG: ETH nonce validation - nonces match:", ethNonces[newEthAddress] == ethNonce);
        
        // Log all relevant nonces for debugging
        console.log("DEBUG: All nonces at this point:");
        console.log("  - ethNonces[oldEthAddress]:", ethNonces[oldEthAddress]);
        console.log("  - ethNonces[newEthAddress]:", ethNonces[newEthAddress]);
        console.log("  - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        
        // Additional debug info before nonce validation
        console.log("DEBUG: About to validate nonces:");
        console.log("  - Will check pqKeyNonces[", uint256(uint160(recoveredFingerprint)), "] == ", pqNonce);
        console.log("  - Will check ethNonces[", uint256(uint160(newEthAddress)), "] == ", ethNonce);
        
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[newEthAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 8: Complete the change
        epervierKeyToAddress[recoveredFingerprint] = newEthAddress;
        addressToEpervierKey[oldEthAddress] = address(0);
        addressToEpervierKey[newEthAddress] = recoveredFingerprint;
        
        // STEP 9: Clear the intent
        delete changeETHAddressIntents[recoveredFingerprint];
        delete ethAddressToChangeIntentFingerprint[oldEthAddress];
        delete ethAddressToChangeIntentFingerprint[newEthAddress];
        
        // STEP 10: Increment nonces
        console.log("DEBUG: confirmChangeETHAddress - Before nonce increments:");
        console.log("  - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        console.log("  - ethNonces[newEthAddress]:", ethNonces[newEthAddress]);
        
        pqKeyNonces[recoveredFingerprint]++;
        ethNonces[newEthAddress]++;
        
        console.log("DEBUG: confirmChangeETHAddress - After nonce increments:");
        console.log("  - pqKeyNonces[recoveredFingerprint]:", pqKeyNonces[recoveredFingerprint]);
        console.log("  - ethNonces[newEthAddress]:", ethNonces[newEthAddress]);
        
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
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ unregistration intent message format
        require(MessageParser.validatePQUnregistrationIntentMessage(pqMessage), "Invalid PQ unregistration intent message");
        
        // STEP 3: Parse the PQ unregistration intent message
        (
            address parsedEthAddress,
            uint256 parsedPQNonce,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = MessageParser.parsePQUnregistrationIntentMessage(pqMessage, DOMAIN_SEPARATOR);
        
        // STEP 4: Parse the base ETH message to get PQ fingerprint and ETH nonce
        (address ethMessagePqFingerprint, uint256 ethNonce) = MessageParser.parseBaseETHUnregistrationIntentMessage(baseETHMessage);
        
        // STEP 5: Validate the base ETH unregistration intent message format
        require(MessageParser.validateBaseETHUnregistrationIntentMessage(baseETHMessage), "Invalid base ETH unregistration intent message");
        
        // STEP 6: Cross-reference validation
        require(parsedEthAddress != address(0), "Invalid intent address");
        address intentAddress = parsedEthAddress;
        address publicKeyAddress = recoveredFingerprint;
        require(intentAddress == epervierKeyToAddress[recoveredFingerprint], "ETH Address mismatch: PQ message vs stored registration");
        require(parsedEthAddress == intentAddress, "ETH Address mismatch in PQ message");
        
        // STEP 7: State validation
        require(addressToEpervierKey[intentAddress] == publicKeyAddress, "Address has no registered Epervier key");
        require(pendingIntents[recoveredFingerprint].timestamp == 0, "Epervier Fingerprint has pending registration intent");
        require(pendingIntents[intentAddress].timestamp == 0, "ETH Address has pending registration intent");
        require(pendingIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(changeETHAddressIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending change intent");
        require(unregistrationIntents[intentAddress].timestamp == 0, "ETH Address has pending unregistration intent");
        
        // STEP 8: Nonce validation
        
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        require(pqKeyNonces[recoveredFingerprint] == parsedPQNonce, "Invalid PQ nonce");
        
        // STEP 9: Verify the ETH signature using EIP712
        bytes32 structHash = SignatureExtractor.getUnregistrationIntentStructHash(ethMessagePqFingerprint, ethNonce);
        
        // DEBUG: Check if we're using the right domain separator
        bytes32 actualDomainSeparator = DOMAIN_SEPARATOR;
        console.log("DEBUG: Contract actualDomainSeparator:", uint256(actualDomainSeparator));
        console.log("DEBUG: Contract actualDomainSeparator hex:", uint256(actualDomainSeparator));
        
        bytes32 digest = SignatureExtractor.getEIP712Digest(actualDomainSeparator, structHash);
        
        // DEBUG: Show what the contract is computing
        console.log("DEBUG: Contract structHash:", uint256(structHash));
        console.log("DEBUG: Contract digest:", uint256(digest));
        console.log("DEBUG: Contract ethNonce:", ethNonce);
        console.log("DEBUG: Contract DOMAIN_SEPARATOR:", uint256(DOMAIN_SEPARATOR));
        
        address ethSigner = ECDSA.recover(digest, v, r, s);
        require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        // STEP 10: Store the unregistration intent
        unregistrationIntents[intentAddress] = UnregistrationIntent({
            publicKey: publicKey,
            publicKeyAddress: publicKeyAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp
        });
        ethAddressToUnregistrationFingerprint[intentAddress] = publicKeyAddress;
        ethAddressToUnregistrationFingerprint[publicKeyAddress] = intentAddress;
        
        // STEP 11: Increment nonces
        ethNonces[intentAddress]++;
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
        // STEP 1: Parse the ETH unregistration confirmation message to get nonce
        uint256 ethNonce = MessageParser.extractEthNonce(ethMessage, 0);
        console.log("DEBUG: Contract extracted ethNonce:", ethNonce);
        
        // STEP 2: Parse PQ signature components from the ETH message
        console.log("DEBUG: Contract ethMessage length:", ethMessage.length);
        console.log("DEBUG: Contract ethMessage first 100 bytes:");
        for (uint i = 0; i < 100 && i < ethMessage.length; i++) {
            console.log("  byte", i, ":", uint8(ethMessage[i]));
        }
        
        // Calculate expected offsets for unregistration message type 2
        uint256 patternLength = 49; // "Confirm unregistration from Epervier Fingerprint "
        uint256 pqFingerprintLength = 20;
        uint256 baseMessageLength = 124; // BasePQUnregistrationConfirmMessage
        uint256 saltStart = patternLength + pqFingerprintLength + baseMessageLength;
        uint256 cs1Start = saltStart + 40;
        uint256 cs2Start = cs1Start + 32*32;
        uint256 hintStart = cs2Start + 32*32;
        
        console.log("DEBUG: Contract expected offsets for message type 2:");
        console.log("  patternLength:", patternLength);
        console.log("  pqFingerprintLength:", pqFingerprintLength);
        console.log("  baseMessageLength:", baseMessageLength);
        console.log("  saltStart:", saltStart);
        console.log("  cs1Start:", cs1Start);
        console.log("  cs2Start:", cs2Start);
        console.log("  hintStart:", hintStart);
        
        bytes memory salt = MessageParser.extractPQSalt(ethMessage, 2);
        uint256[] memory cs1 = MessageParser.extractPQCs1(ethMessage, 2);
        uint256[] memory cs2 = MessageParser.extractPQCs2(ethMessage, 2);
        uint256 hint = MessageParser.extractPQHint(ethMessage, 2);
        bytes memory basePQMessage = MessageParser.extractBasePQMessage(ethMessage, 2);
        
        uint256[32] memory cs1Array;
        uint256[32] memory cs2Array;
        for (uint i = 0; i < 32; i++) {
            cs1Array[i] = cs1[i];
            cs2Array[i] = cs2[i];
        }
        
        // STEP 3: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        console.log("DEBUG: Contract recoveredFingerprint:", uint256(uint160(recoveredFingerprint)));
        
        // STEP 4: Parse the fingerprint address from the ETH message
        address fingerprintAddress = MessageParser.parseETHAddressFromETHUnregistrationConfirmationMessage(ethMessage);
        console.log("DEBUG: Contract fingerprintAddress from message:", uint256(uint160(fingerprintAddress)));
        require(fingerprintAddress == recoveredFingerprint, "Fingerprint address mismatch: ETH message vs recovered PQ signature");
        
        // STEP 5: Verify the ETH signature using EIP712
        bytes32 structHash = SignatureExtractor.getUnregistrationConfirmationStructHash(
            fingerprintAddress,
            basePQMessage,
            salt,
            cs1Array,
            cs2Array,
            hint,
            ethNonce
        );
        bytes32 digest = SignatureExtractor.getEIP712Digest(DOMAIN_SEPARATOR, structHash);
        
        // DEBUG: Log EIP712 signature verification details
        console.log("DEBUG: Contract EIP712 signature verification:");
        console.log("  DOMAIN_SEPARATOR:", uint256(DOMAIN_SEPARATOR));
        console.log("  structHash:", uint256(structHash));
        console.log("  digest:", uint256(digest));
        console.log("  signature v:", v);
        console.log("  signature r:", uint256(r));
        console.log("  signature s:", uint256(s));
        
        address recoveredETHAddress = ECDSA.recover(digest, v, r, s);
        console.log("DEBUG: Contract recoveredETHAddress:", uint256(uint160(recoveredETHAddress)));
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 5: Parse the base PQ message
        (address basePQEthAddress, ) = MessageParser.parseBasePQUnregistrationConfirmMessage(basePQMessage, DOMAIN_SEPARATOR);
        console.log("DEBUG: Contract basePQEthAddress:", uint256(uint160(basePQEthAddress)));
        
        // STEP 6: Cross-reference validationETH Address mismatch: PQ message vs stored registration
        address intentAddress = epervierKeyToAddress[recoveredFingerprint];
        console.log("DEBUG: Contract intentAddress from mapping:", uint256(uint160(intentAddress)));
        require(intentAddress != address(0), "ETH Address not registered to PQ fingerprint");
        console.log("DEBUG: Contract address comparison:");
        console.log("  intentAddress:", uint256(uint160(intentAddress)));
        console.log("  recoveredETHAddress:", uint256(uint160(recoveredETHAddress)));
        require(intentAddress == recoveredETHAddress, "ETH signature must be from registered address");
        require(basePQEthAddress == intentAddress, "ETH address mismatch: base PQ message vs intent address");
        
        // STEP 7: State validation
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found for ETH Address");
        require(intent.publicKeyAddress == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // STEP 8: Extract and validate nonces
        uint256 pqNonce = MessageParser.extractPQNonce(basePQMessage, 0);
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // STEP 9: Verify message content
        require(MessageParser.validateETHUnregistrationConfirmationMessage(ethMessage), "Invalid ETH confirmation message");
        require(MessageParser.validatePQUnregistrationConfirmationMessage(basePQMessage), "Invalid PQ confirmation message");
        
        // STEP 10: Remove the mappings
        epervierKeyToAddress[recoveredFingerprint] = address(0);
        addressToEpervierKey[intentAddress] = address(0);
        
        // STEP 11: Clear the intent
        delete unregistrationIntents[intentAddress];
        delete ethAddressToUnregistrationFingerprint[intentAddress];
        delete ethAddressToUnregistrationFingerprint[recoveredFingerprint];
        
        // STEP 12: Increment nonces
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
        
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Extract PQ nonce from the PQ message
        uint256 pqNonce = MessageParser.extractPQNonceFromRemoveMessage(pqMessage);
        
        // STEP 3: Parse the ETH Address from the PQ message
        (address intentAddress, ) = MessageParser.parsePQRemoveUnregistrationIntentMessage(pqMessage, DOMAIN_SEPARATOR);
        require(intentAddress != address(0), "Invalid intent address");
        
        // STEP 4: State validation
        address publicKeyAddress = recoveredFingerprint;
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found");
        require(intent.publicKeyAddress == publicKeyAddress, "PQ key mismatch");
        
        // STEP 5: Nonce validation
        
        require(pqKeyNonces[publicKeyAddress] == pqNonce, "Invalid PQ nonce");
        
        // STEP 6: Verify the PQ message contains the correct removal text
        require(MessageParser.validatePQUnregistrationRemovalMessage(pqMessage), "Invalid PQ removal message");
        
        // STEP 7: Clear the intent
        delete unregistrationIntents[intentAddress];
        delete ethAddressToUnregistrationFingerprint[intentAddress];
        delete ethAddressToUnregistrationFingerprint[publicKeyAddress];

        // STEP 8: Increment nonce
        pqKeyNonces[publicKeyAddress]++;
        

        emit UnregistrationIntentRemoved(publicKeyAddress);
    }
    
    // ============================================================================
    // PQ SIGNATURE VERIFICATION AND NFT MINTING
    // ============================================================================
    
    /**
     * @dev Get the registered address for a PQ fingerprint
     * @param pqFingerprint The PQ fingerprint
     * @return The registered ETH address (address(0) if not registered)
     */
    function getRegisteredAddress(address pqFingerprint) external view returns (address) {
        return epervierKeyToAddress[pqFingerprint];
    }
    
    /**
     * @dev Register an NFT contract to enable minting
     * @param nftContract The NFT contract address
     *
     * NOTE: At least one NFT contract must be registered before registration or minting is allowed.
     */
    function registerNFTContract(address nftContract) external {
        require(nftContract != address(0), "Invalid NFT contract address");
        if (!registeredNFTContracts[nftContract]) {
            registeredNFTContracts[nftContract] = true;
            registeredNFTContractAddresses.push(nftContract);
            registeredNFTContractCount++;
        }
    }
    
    /**
     * @dev Unregister an NFT contract
     * @param nftContract The NFT contract address
     */
    function unregisterNFTContract(address nftContract) external {
        if (registeredNFTContracts[nftContract]) {
            registeredNFTContracts[nftContract] = false;
            registeredNFTContractCount--;
        }
    }
    
    /**
     * @dev Mint an NFT when a fingerprint is paired
     * This function is called by the NFT contract when a fingerprint is registered
     * @param pqFingerprint The PQ fingerprint
     * @param ethAddress The ETH address associated with the fingerprint
     * @param nftContract The NFT contract address
     */
    function mintNFTForFingerprint(
        address pqFingerprint,
        address ethAddress,
        address nftContract
    ) external {
        require(registeredNFTContractCount > 0, "No NFT contract registered");
        require(registeredNFTContracts[nftContract], "NFT contract not registered");
        require(msg.sender == nftContract, "Only registered NFT contract can mint");
        require(pqFingerprint != address(0), "Invalid PQ fingerprint");
        require(ethAddress != address(0), "Invalid ETH address");
        
        // Verify that the fingerprint is registered to this ETH address
        require(epervierKeyToAddress[pqFingerprint] == ethAddress, "Fingerprint not registered to ETH address");
        
        // Call the NFT contract's mint function
        // The NFT contract will handle the actual minting
        emit NFTMinted(nftContract, pqFingerprint, ethAddress, 0); // tokenId will be set by NFT contract
    }
    
    /**
     * @dev Check if a fingerprint is registered
     * @param pqFingerprint The PQ fingerprint to check
     * @return True if the fingerprint is registered
     */
    function isFingerprintRegistered(address pqFingerprint) external view returns (bool) {
        return epervierKeyToAddress[pqFingerprint] != address(0);
    }
    
    /**
     * @dev Check if an ETH address is registered
     * @param ethAddress The ETH address to check
     * @return True if the address is registered
     */
    function isAddressRegistered(address ethAddress) external view returns (bool) {
        return addressToEpervierKey[ethAddress] != address(0);
    }
} 