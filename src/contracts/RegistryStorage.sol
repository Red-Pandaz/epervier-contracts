// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../interfaces/IMessageParser.sol";
import "../interfaces/IMessageValidation.sol";
import "../interfaces/ISignatureExtractor.sol";
import "../interfaces/IAddressUtils.sol";
import "../interfaces/IEpervierVerifier.sol";
import "../interfaces/IRegistrationLogic.sol";
import "../interfaces/IUnregistrationLogic.sol";
import "../interfaces/IChangeAddressLogic.sol";

library RegistryStorage {
    bytes32 internal constant STORAGE_SLOT = keccak256("epervier.registry.storage");

    struct Intent {
        address pqFingerprint;
        bytes intentMessage;
        uint256 timestamp;
    }

    struct UnregistrationIntent {
        uint256 timestamp;
        uint256[2] publicKey;
        address publicKeyAddress;
        bytes pqMessage;
    }

    struct ChangeETHAddressIntent {
        address newETHAddress;
        address oldETHAddress;
        uint256 timestamp;
        uint256 pqNonce;
    }

    struct Layout {
        // External contracts
        IEpervierVerifier epervierVerifier;
        IMessageParser messageParser;
        IMessageValidation messageValidation;
        ISignatureExtractor signatureExtractor;
        IAddressUtils addressUtils;

        // Domain separator
        bytes32 DOMAIN_SEPARATOR;

        // NFT contract tracking
        mapping(address => bool) registeredNFTContracts;
        address[] registeredNFTContractAddresses;
        uint256 registeredNFTContractCount;

        // Registration state
        mapping(address => Intent) pendingIntents;
        mapping(address => address) pqFingerprintToPendingIntentAddress;
        mapping(address => address) epervierKeyToAddress;
        mapping(address => address) addressToEpervierKey;
        mapping(address => uint256) ethNonces;
        mapping(address => uint256) pqKeyNonces;
        
        // Unregistration state
        mapping(address => UnregistrationIntent) unregistrationIntents;
        mapping(address => address) ethAddressToUnregistrationFingerprint;
        
        // Change address state
        mapping(address => ChangeETHAddressIntent) changeETHAddressIntents;
        mapping(address => address) ethAddressToChangeIntentFingerprint;

        // Logic contract references for modular pattern
        IRegistrationLogic registrationLogic;
        IUnregistrationLogic unregistrationLogic;
        IChangeAddressLogic changeAddressLogic;
    }

    function layout() internal pure returns (Layout storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /**
     * @dev Debug function to get the storage slot
     * @return The storage slot being used
     */
    function getStorageSlot() internal pure returns (bytes32) {
        return STORAGE_SLOT;
    }
} 