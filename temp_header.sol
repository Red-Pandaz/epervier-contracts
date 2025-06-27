// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./libraries/MessageParser.sol";
import "./libraries/MessageValidation.sol";
import "./libraries/SignatureExtractor.sol";
import "./libraries/AddressUtils.sol";

// TODO: Add a function that allows ETH Address to remove ChangeEThAddressIntent
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
    
    // Nonces for ETH Addresses (per domain)
    mapping(address => uint256) public ethNonces;
    
    // Nonces for PQ keys (existing)
    mapping(address => uint256) public pqKeyNonces;
    
    // Pending intents for two-step registration - ETH Address controls their intent
    struct Intent {
        address pqFingerprint;
        bytes intentMessage;
        uint256 timestamp;
    }
    mapping(address => Intent) public pendingIntents;
    
    // Bidirectional mapping: PQ fingerprint to ETH Address with pending intent
    mapping(address => address) public pqFingerprintToPendingIntentAddress;
    
    // Pending change ETH Address intents - PQ key controls their intent
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
    event DebugAddress(string label, address addr);
    
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
