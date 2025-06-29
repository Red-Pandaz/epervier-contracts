// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./libraries/MessageParser.sol";
import "./libraries/MessageValidation.sol";
import "./libraries/SignatureExtractor.sol";
import "./libraries/AddressUtils.sol";

interface IEpervierVerifier {
    function recover(bytes memory, bytes memory, uint256[] memory, uint256[] memory, uint256) external returns (address);
}

interface IConsole {
    function log(string memory) external;
    function log(string memory, uint256) external;
    function log(string memory, address) external;
}

contract PQRegistry {
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
    IConsole public console;
    
    // EIP-712 Domain Separator
    string public constant DOMAIN_NAME = "PQRegistry";
    string public constant DOMAIN_VERSION = "1";
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor(
        address _epervierVerifier,
        address _console
    ) {
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        require(_console != address(0), "Console cannot be zero address");
        
        epervierVerifier = IEpervierVerifier(_epervierVerifier);
        console = IConsole(_console);
        
        // Compute EIP-712 domain separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(DOMAIN_NAME)),
                keccak256(bytes(DOMAIN_VERSION)),
                11155420, // Optimism Sepolia chain ID
                address(this)
            )
        );
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
        // STEP 1: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // Debug logging
        emit DebugParseStep("eth_message_length", ethMessage.length);
        emit DebugParseStep("eth_message_hash", uint256(ethMessageHash));
        emit DebugParseStep("eth_signed_message_hash", uint256(ethSignedMessageHash));
        emit DebugParseStep("eth_signature_recovered", uint256(uint160(recoveredETHAddress)));
    
        // STEP 2: Parse the ETH registration intent message
        (
            uint256 ethNonce,
            bytes memory salt,
            uint256[] memory cs1,
            uint256[] memory cs2,
            uint256 hint,
            bytes memory basePQMessage
        ) = MessageParser.parseETHRegistrationIntentMessage(ethMessage);
        
        // STEP 3: Parse the base PQ message
        (address intentAddress, uint256 pqNonce) = MessageParser.parseBasePQRegistrationIntentMessage(basePQMessage);
        
        // Debug logging for address comparison
        emit DebugParseStep("recovered_eth_address", uint256(uint160(recoveredETHAddress)));
        emit DebugParseStep("parsed_intent_address", uint256(uint160(intentAddress)));
        emit DebugParseStep("addresses_equal", uint256(uint160(recoveredETHAddress == intentAddress ? 1 : 0)));
        
        // STEP 4: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        
        // STEP 5: Cross-reference validation
        require(intentAddress == recoveredETHAddress, "ETH signature must be from intent address");
        
        // STEP 6: State validation
        require(pendingIntents[recoveredETHAddress].timestamp == 0, "ETH Address has pending registration intent");
        require(ethAddressToChangeIntentFingerprint[recoveredETHAddress] == address(0), "ETH Address has pending change intent");
        require(unregistrationIntents[recoveredETHAddress].timestamp == 0 && ethAddressToUnregistrationFingerprint[recoveredETHAddress] == address(0), "ETH Address has pending unregistration intent");
        require(pendingIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        require(unregistrationIntents[recoveredFingerprint].timestamp == 0 && ethAddressToUnregistrationFingerprint[recoveredFingerprint] == address(0), "PQ fingerprint has pending unregistration intent");
        
        // STEP 7: Nonce validation
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 8: Store the intent
        pendingIntents[intentAddress] = Intent({
            pqFingerprint: recoveredFingerprint,
            intentMessage: basePQMessage,
            timestamp: block.timestamp
        });
        
        // STEP 9: Store the bidirectional mapping
        pqFingerprintToPendingIntentAddress[recoveredFingerprint] = intentAddress;
        
        // STEP 10: Increment nonces
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
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Validate the PQ registration confirmation message format
        require(MessageParser.validatePQRegistrationConfirmationMessage(pqMessage), "Invalid PQ registration confirmation message");
        
        // STEP 3: Parse the PQ registration confirmation message
        (
            address ethAddress,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s,
            uint256 pqNonce
        ) = MessageParser.parsePQRegistrationConfirmationMessage(pqMessage);
        
        // STEP 4: Parse the base ETH confirmation message
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseBaseETHRegistrationConfirmationMessage(baseETHMessage);
        
        // STEP 5: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(baseETHMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(baseETHMessage.length), baseETHMessage));
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");

        // STEP 6: Cross-reference validation
        require(ethAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        require(pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // STEP 7: State validation - Check PQ fingerprint mapping first
        address intentAddress = pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        require(intentAddress != address(0), "No pending intent found for PQ fingerprint");
        
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for ETH Address");
        require(intentAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs stored intent");
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        
        // STEP 8: Comprehensive conflict prevention check
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 9: Nonce validation
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[ethAddress] == ethNonce, "Invalid ETH nonce");

        // STEP 10: Complete the registration
        epervierKeyToAddress[recoveredFingerprint] = ethAddress;
        addressToEpervierKey[ethAddress] = recoveredFingerprint;
        
        // STEP 11: Clear the pending intent and bidirectional mapping
        delete pendingIntents[ethAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // STEP 12: Increment nonces
        pqKeyNonces[recoveredFingerprint]++;
        ethNonces[ethAddress]++;
        
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
        // STEP 1: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 2: Parse the ETH remove intent message
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseETHRemoveRegistrationIntentMessage(ethMessage);
        
        // STEP 3: State validation
        Intent storage intent = pendingIntents[recoveredETHAddress];
        require(intent.timestamp != 0, "No pending intent found for recovered ETH Address");
        require(intent.pqFingerprint == pqFingerprint, "PQ fingerprint mismatch: ETH message vs stored intent");
        require(pqFingerprintToPendingIntentAddress[pqFingerprint] == recoveredETHAddress, "Bidirectional mapping mismatch");
        
        // STEP 4: Comprehensive conflict prevention check
        require(pendingIntents[recoveredETHAddress].timestamp != 0, "ETH Address does not have pending registration intent");
        require(pqFingerprintToPendingIntentAddress[pqFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 5: Nonce validation
        require(ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 6: Store the PQ fingerprint before clearing the intent
        address pqFingerprintToClear = intent.pqFingerprint;
        
        // STEP 7: Clear the intent
        delete pendingIntents[recoveredETHAddress];
        delete pqFingerprintToPendingIntentAddress[pqFingerprintToClear];
        
        // STEP 8: Increment nonce
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
        
        Intent storage intent = pendingIntents[intentAddress];
        require(intent.timestamp != 0, "No pending intent found for referenced ETH Address");
        require(intent.pqFingerprint == recoveredFingerprint, "PQ fingerprint mismatch: recovered vs stored intent");
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] == intentAddress, "Bidirectional mapping mismatch");
        
        // STEP 4: Comprehensive conflict prevention check
        require(pendingIntents[intentAddress].timestamp != 0, "ETH Address does not have pending registration intent");
        require(pqFingerprintToPendingIntentAddress[recoveredFingerprint] != address(0), "PQ fingerprint does not have pending registration intent");
        
        // STEP 5: Nonce validation
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // STEP 6: Verify the PQ message contains the correct removal text
        require(MessageParser.validatePQRemoveIntentMessage(pqMessage), "Invalid PQ removal message");
        
        // STEP 7: Clear both mappings
        delete pendingIntents[intentAddress];
        delete pqFingerprintToPendingIntentAddress[recoveredFingerprint];
        
        // STEP 8: Increment nonce
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
        // STEP 1: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 2: Parse the ETH remove change intent message
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseETHRemoveChangeIntentMessage(ethMessage);
        
        // STEP 3: State validation
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[pqFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        require(ethAddressToChangeIntentFingerprint[recoveredETHAddress] == pqFingerprint, "ETH Address not registered to PQ fingerprint");
        require(intent.newETHAddress == recoveredETHAddress, "ETH Address not the new address in change intent");
        
        // DEBUG: Print addresses for debugging
        console.log("DEBUG: Recovered ETH address:", recoveredETHAddress);
        console.log("DEBUG: New ETH address in intent:", intent.newETHAddress);
        console.log("DEBUG: PQ fingerprint:", pqFingerprint);
        
        // STEP 4: Comprehensive conflict prevention check
        require(changeETHAddressIntents[pqFingerprint].timestamp != 0, "PQ fingerprint does not have pending change intent");
        
        // STEP 5: Nonce validation
        require(ethNonces[recoveredETHAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 6: Clear the intent
        delete changeETHAddressIntents[pqFingerprint];
        delete ethAddressToChangeIntentFingerprint[recoveredETHAddress];
        delete ethAddressToChangeIntentFingerprint[epervierKeyToAddress[pqFingerprint]];
        
        // STEP 7: Increment nonce
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
        
        // STEP 4: State validation
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        require(epervierKeyToAddress[recoveredFingerprint] == ethAddress, "ETH Address not the current address for PQ fingerprint");
        
        // DEBUG: Print addresses for debugging
        console.log("DEBUG PQ Cancel: ETH address from message:", ethAddress);
        console.log("DEBUG PQ Cancel: Current ETH address for PQ fingerprint:", epervierKeyToAddress[recoveredFingerprint]);
        console.log("DEBUG PQ Cancel: New ETH address in intent:", intent.newETHAddress);
        console.log("DEBUG PQ Cancel: PQ fingerprint:", recoveredFingerprint);
        
        // STEP 5: Verify ETH address is registered to this PQ fingerprint
        require(epervierKeyToAddress[recoveredFingerprint] == ethAddress, "ETH address not registered to PQ fingerprint");
        
        // STEP 6: Verify there's a pending change intent
        require(intent.newETHAddress != address(0), "No pending change intent");
        require(intent.timestamp > 0, "No pending change intent");
        
        // STEP 7: Nonce validation
        // DEBUG: Print PQ nonce in message and contract
        console.log("DEBUG: PQ nonce in message:", pqNonce);
        console.log("DEBUG: PQ nonce in contract:", pqKeyNonces[recoveredFingerprint]);
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        
        // STEP 8: Clear the intent
        delete changeETHAddressIntents[recoveredFingerprint];
        delete ethAddressToChangeIntentFingerprint[ethAddress];
        delete ethAddressToChangeIntentFingerprint[epervierKeyToAddress[recoveredFingerprint]];
        
        // STEP 9: Increment nonce
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
        
        // STEP 2: Parse the PQ change address intent message
        (address oldEthAddress, address newEthAddress, uint256 pqNonce, bytes memory baseETHMessage, uint8 v, bytes32 r, bytes32 s) = MessageParser.parsePQChangeETHAddressIntentMessage(pqMessage);
        
        // STEP 3: Parse the base ETH message
        (address ethMessagePqFingerprint, address ethMessageNewEthAddress, uint256 ethNonce) = MessageParser.parseBaseETHChangeETHAddressIntentMessage(baseETHMessage);
        
        // STEP 4: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(baseETHMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(baseETHMessage.length), baseETHMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 5: Cross-reference validation
        require(newEthAddress == recoveredETHAddress, "ETH signature must be from new ETH Address");
        require(ethMessagePqFingerprint == recoveredFingerprint, "ETH message PQ fingerprint mismatch");
        require(ethMessageNewEthAddress == newEthAddress, "ETH message new ETH Address mismatch");
        
        // STEP 6: State validation
        address currentETHAddress = epervierKeyToAddress[recoveredFingerprint];
        require(currentETHAddress != address(0), "PQ fingerprint not registered");
        require(oldEthAddress == currentETHAddress, "Old ETH Address mismatch: PQ message vs current registration");
        require(addressToEpervierKey[currentETHAddress] == recoveredFingerprint, "PQ key not registered to current address");
        require(newEthAddress != currentETHAddress, "New ETH Address must be different from current address");
        require(addressToEpervierKey[newEthAddress] == address(0), "New ETH Address already has registered PQ key");
        
        // STEP 7: Conflict prevention
        require(changeETHAddressIntents[recoveredFingerprint].timestamp == 0, "PQ fingerprint has pending change intent");
        require(ethAddressToChangeIntentFingerprint[oldEthAddress] == address(0), "Old ETH Address has pending change intent");
        require(ethAddressToChangeIntentFingerprint[newEthAddress] == address(0), "New ETH Address has pending change intent");
        
        // STEP 8: Nonce validation
        require(pqKeyNonces[recoveredFingerprint] == pqNonce, "Invalid PQ nonce");
        require(ethNonces[newEthAddress] == ethNonce, "Invalid ETH nonce");
        
        // STEP 9: Store the change intent
        changeETHAddressIntents[recoveredFingerprint] = ChangeETHAddressIntent({
            newETHAddress: newEthAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp,
            pqNonce: pqKeyNonces[recoveredFingerprint]
        });
        ethAddressToChangeIntentFingerprint[oldEthAddress] = recoveredFingerprint;
        ethAddressToChangeIntentFingerprint[newEthAddress] = recoveredFingerprint;
        
        // STEP 10: Increment nonces
        pqKeyNonces[recoveredFingerprint]++;
        ethNonces[newEthAddress]++;

        emit ChangeETHAddressIntentSubmitted(recoveredFingerprint, newEthAddress, ethNonce);
    }
    
    function confirmChangeETHAddress(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // STEP 1: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
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
        
        // STEP 3: Parse the base PQ change address confirmation message
        (address oldEthAddress, address newEthAddress, uint256 pqNonce) = MessageParser.parseBasePQChangeETHAddressConfirmMessage(basePQMessage);
        
        // STEP 4: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        
        // STEP 5: Cross-reference validation
        require(newEthAddress == recoveredETHAddress, "ETH Address mismatch: PQ message vs recovered ETH signature");
        
        // STEP 6: State validation
        ChangeETHAddressIntent storage intent = changeETHAddressIntents[recoveredFingerprint];
        require(intent.timestamp != 0, "No pending change intent found for PQ fingerprint");
        require(intent.newETHAddress == newEthAddress, "ETH Address mismatch: PQ message vs stored intent");
        require(addressToEpervierKey[oldEthAddress] == recoveredFingerprint, "Old ETH Address mismatch: PQ message vs current registration");
        require(epervierKeyToAddress[recoveredFingerprint] == oldEthAddress, "PQ fingerprint not registered to old ETH Address");

        // STEP 7: Nonce validation
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
        // STEP 1: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
        
        // STEP 2: Parse the PQ unregistration intent message
        (
            address parsedEthAddress,
            uint256 parsedPQNonce,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = MessageParser.parsePQUnregistrationIntentMessage(pqMessage);
        
        // STEP 3: Extract ETH nonce from the baseETHMessage
        uint256 ethNonce = MessageParser.extractEthNonce(baseETHMessage, 0);
        
        // STEP 4: Cross-reference validation
        require(parsedEthAddress != address(0), "Invalid intent address");
        address intentAddress = parsedEthAddress;
        address publicKeyAddress = recoveredFingerprint;
        require(intentAddress == epervierKeyToAddress[recoveredFingerprint], "ETH Address mismatch: PQ message vs stored registration");
        require(parsedEthAddress == intentAddress, "ETH Address mismatch in PQ message");
        
        // STEP 5: State validation
        require(addressToEpervierKey[intentAddress] == publicKeyAddress, "Address has no registered Epervier key");
        require(pendingIntents[recoveredFingerprint].timestamp == 0, "Epervier Fingerprint has pending registration intent");
        require(pendingIntents[intentAddress].timestamp == 0, "ETH Address has pending registration intent");
        require(pendingIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending registration intent");
        require(changeETHAddressIntents[publicKeyAddress].timestamp == 0, "PQ fingerprint has pending change intent");
        require(unregistrationIntents[intentAddress].timestamp == 0, "ETH Address has pending unregistration intent");
        
        // STEP 6: Nonce validation
        require(ethNonces[intentAddress] == ethNonce, "Invalid ETH nonce");
        require(pqKeyNonces[publicKeyAddress] == parsedPQNonce, "Invalid PQ nonce");
        
        // STEP 7: Verify the ETH signature
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(baseETHMessage.length), baseETHMessage));
        address ethSigner = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(ethSigner == intentAddress, "ETH signature must be from intent address");
        
        // STEP 8: Store the unregistration intent
        unregistrationIntents[intentAddress] = UnregistrationIntent({
            publicKey: publicKey,
            publicKeyAddress: publicKeyAddress,
            pqMessage: pqMessage,
            timestamp: block.timestamp
        });
        ethAddressToUnregistrationFingerprint[intentAddress] = publicKeyAddress;
        ethAddressToUnregistrationFingerprint[publicKeyAddress] = intentAddress;
        
        // STEP 9: Increment nonces
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
        // STEP 1: Verify the ETH signature
        bytes32 ethMessageHash = keccak256(ethMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        
        address recoveredETHAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        require(recoveredETHAddress != address(0), "Invalid ETH signature");
        
        // STEP 2: Parse PQ signature components from the ETH message
        bytes memory salt = MessageParser.extractPQSalt(ethMessage, 2);
        uint256[] memory cs1 = MessageParser.extractPQCs1(ethMessage, 2);
        uint256[] memory cs2 = MessageParser.extractPQCs2(ethMessage, 2);
        uint256 hint = MessageParser.extractPQHint(ethMessage, 2);
        bytes memory basePQMessage = MessageParser.extractBasePQMessage(ethMessage, 2);
        
        // STEP 3: Verify the PQ signature and recover the fingerprint
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        
        // STEP 4: Parse the fingerprint address from the ETH message
        address fingerprintAddress = MessageParser.parseETHAddressFromETHUnregistrationConfirmationMessage(ethMessage);
        require(fingerprintAddress == recoveredFingerprint, "Fingerprint address mismatch: ETH message vs recovered PQ signature");
        
        // STEP 5: Parse the base PQ message
        (address basePQEthAddress, ) = MessageParser.parseBasePQUnregistrationConfirmMessage(basePQMessage);
        
        // STEP 6: Cross-reference validation
        address intentAddress = epervierKeyToAddress[recoveredFingerprint];
        require(intentAddress != address(0), "ETH Address not registered to PQ fingerprint");
        require(intentAddress == recoveredETHAddress, "ETH signature must be from registered address");
        require(basePQEthAddress == intentAddress, "ETH address mismatch: base PQ message vs intent address");
        
        // STEP 7: State validation
        UnregistrationIntent storage intent = unregistrationIntents[intentAddress];
        require(intent.timestamp != 0, "No pending unregistration intent found for ETH Address");
        require(intent.publicKeyAddress == recoveredFingerprint, "PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        
        // STEP 8: Extract and validate nonces
        uint256 ethNonce = MessageParser.extractEthNonce(basePQMessage, 1);
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
        (address intentAddress, ) = MessageParser.parsePQRemoveUnregistrationIntentMessage(pqMessage);
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
} 