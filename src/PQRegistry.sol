// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./interfaces/IMessageParser.sol";
import "./interfaces/IMessageValidation.sol";
import "./interfaces/ISignatureExtractor.sol";
import "./interfaces/IAddressUtils.sol";
import "./interfaces/IEpervierVerifier.sol";
import "./interfaces/IPQERC721.sol";
import "./interfaces/IRegistrationLogic.sol";
import "./interfaces/IUnregistrationLogic.sol";
import "./interfaces/IChangeAddressLogic.sol";
import "./contracts/RegistryStorage.sol";


contract PQRegistry {
    using ECDSA for bytes32;
    using Strings for string;
    using RegistryStorage for RegistryStorage.Layout;
    
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
    event NFTMinted(address indexed nftContract, address indexed pqFingerprint, address indexed ethAddress, uint256 tokenId);
    
    // --- External dependencies ---
    // All external contracts are now accessed via RegistryStorage.layout()
    
    // --- Constructor ---
    constructor(
        address _epervierVerifier,
        address _messageParser,
        address _messageValidation,
        address _signatureExtractor,
        address _addressUtils,
        address _registrationLogic,
        address _unregistrationLogic,
        address _changeAddressLogic
    ) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
        require(_messageParser != address(0), "MessageParser cannot be zero address");
        require(_messageValidation != address(0), "MessageValidation cannot be zero address");
        require(_signatureExtractor != address(0), "SignatureExtractor cannot be zero address");
        require(_addressUtils != address(0), "AddressUtils cannot be zero address");
        require(_registrationLogic != address(0), "RegistrationLogic cannot be zero address");
        require(_unregistrationLogic != address(0), "UnregistrationLogic cannot be zero address");
        require(_changeAddressLogic != address(0), "ChangeAddressLogic cannot be zero address");
        s.epervierVerifier = IEpervierVerifier(_epervierVerifier);
        s.messageParser = IMessageParser(_messageParser);
        s.messageValidation = IMessageValidation(_messageValidation);
        s.signatureExtractor = ISignatureExtractor(_signatureExtractor);
        s.addressUtils = IAddressUtils(_addressUtils);
        s.registrationLogic = IRegistrationLogic(_registrationLogic);
        s.unregistrationLogic = IUnregistrationLogic(_unregistrationLogic);
        s.changeAddressLogic = IChangeAddressLogic(_changeAddressLogic);
        // Initialize EIP-712 domain separator
        s.DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PQRegistry")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }
    
    /**
     * @dev Initialize the registry with NFT contracts
     * This can be called after deployment to register NFT contracts
     * @param nftContracts Array of NFT contract addresses to register
     */
    function initializeNFTContracts(address[] memory nftContracts) external {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        for (uint256 i = 0; i < nftContracts.length; i++) {
            require(nftContracts[i] != address(0), "Invalid NFT contract address");
            s.registeredNFTContracts[nftContracts[i]] = true;
            s.registeredNFTContractAddresses.push(nftContracts[i]);
            s.registeredNFTContractCount++;
        }
    }
    
    // --- Main functions ---
    function submitRegistrationIntent(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        require(storage_s.registeredNFTContractCount > 0, "No NFT contract registered");
        (bool success, bytes memory returnData) = address(storage_s.registrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.registrationLogic.submitRegistrationIntent.selector,
                ethMessage,
                v,
                r,
                s
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Registration logic call failed - no revert data");
            }
        }
    }

    /**
     * @dev Confirm a registration intent with PQ signature
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
        (bool success, bytes memory returnData) = address(storage_s.registrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.registrationLogic.confirmRegistration.selector,
                pqMessage,
                salt,
                cs1,
                cs2,
                hint
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Registration logic call failed - no revert data");
            }
        }
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
        (bool success, bytes memory returnData) = address(storage_s.registrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.registrationLogic.removeRegistrationIntentByETH.selector,
                ethMessage,
                v,
                r,
                s
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Registration logic call failed - no revert data");
            }
        }
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
        (bool success, bytes memory returnData) = address(storage_s.registrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.registrationLogic.removeRegistrationIntentByPQ.selector,
                pqMessage,
                salt,
                cs1,
                cs2,
                hint
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Registration logic call failed - no revert data");
            }
        }
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
        (bool success, bytes memory returnData) = address(storage_s.changeAddressLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.changeAddressLogic.removeChangeETHAddressIntentByETH.selector,
                ethMessage,
                v,
                r,
                s
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Change address logic call failed - no revert data");
            }
        }
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
        (bool success, bytes memory returnData) = address(storage_s.changeAddressLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.changeAddressLogic.removeChangeETHAddressIntentByPQ.selector,
                pqMessage,
                salt,
                cs1,
                cs2,
                hint
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Change address logic call failed - no revert data");
            }
        }
    }

    function submitChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        (bool success, bytes memory returnData) = address(storage_s.changeAddressLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.changeAddressLogic.submitChangeETHAddressIntent.selector,
                pqMessage,
                salt,
                cs1,
                cs2,
                hint
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Change address logic call failed - no revert data");
            }
        }
    }
    
    function confirmChangeETHAddress(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        (bool success, bytes memory returnData) = address(storage_s.changeAddressLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.changeAddressLogic.confirmChangeETHAddress.selector,
                ethMessage,
                v,
                r,
                s
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Change address logic call failed - no revert data");
            }
        }
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
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        (bool success, bytes memory returnData) = address(storage_s.unregistrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.unregistrationLogic.submitUnregistrationIntent.selector,
                pqMessage,
                salt,
                cs1,
                cs2,
                hint
            )
        );
        if (!success) {
            // Decode the revert reason if possible
            if (returnData.length > 0) {
                // Try to decode as a revert reason string
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Unregistration logic call failed - no revert data");
            }
        }
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
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        (bool success, bytes memory returnData) = address(storage_s.unregistrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.unregistrationLogic.confirmUnregistration.selector,
                ethMessage,
                v,
                r,
                s
            )
        );
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Unregistration logic call failed - no revert data");
            }
        }
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
    ) external returns (address pqFingerprint) {
        RegistryStorage.Layout storage storage_s = RegistryStorage.layout();
        (bool success, bytes memory returnData) = address(storage_s.unregistrationLogic).delegatecall(
            abi.encodeWithSelector(
                storage_s.unregistrationLogic.removeUnregistrationIntent.selector,
                pqMessage,
                salt,
                cs1,
                cs2,
                hint
            )
        );
        if (!success) {
            // Decode the revert reason if possible
            if (returnData.length > 0) {
                // Try to decode as a revert reason string
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert("Unregistration logic call failed - no revert data");
            }
        }
        return abi.decode(returnData, (address));
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
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.epervierKeyToAddress[pqFingerprint];
    }
    
    /**
     * @dev Register an NFT contract to enable minting
     * @param nftContract The NFT contract address
     *
     * NOTE: At least one NFT contract must be registered before registration or minting is allowed.
     */
    function registerNFTContract(address nftContract) external {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        require(nftContract != address(0), "Invalid NFT contract address");
        if (!s.registeredNFTContracts[nftContract]) {
            s.registeredNFTContracts[nftContract] = true;
            s.registeredNFTContractAddresses.push(nftContract);
            s.registeredNFTContractCount++;
        }
    }
    
    /**
     * @dev Unregister an NFT contract
     * @param nftContract The NFT contract address
     */
    function unregisterNFTContract(address nftContract) external {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        if (s.registeredNFTContracts[nftContract]) {
            s.registeredNFTContracts[nftContract] = false;
            s.registeredNFTContractCount--;
        }
    }
    
    /**
     * @dev Mint an NFT when a fingerprint is bound
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
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        require(s.registeredNFTContractCount > 0, "No NFT contract registered");
        require(s.registeredNFTContracts[nftContract], "NFT contract not registered");
        require(msg.sender == nftContract, "Only registered NFT contract can mint");
        require(pqFingerprint != address(0), "Invalid PQ fingerprint");
        require(ethAddress != address(0), "Invalid ETH address");
        
        // Verify that the fingerprint is registered to this ETH address
        require(s.epervierKeyToAddress[pqFingerprint] == ethAddress, "Fingerprint not registered to ETH address");
        
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
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.epervierKeyToAddress[pqFingerprint] != address(0);
    }
    
    /**
     * @dev Check if an ETH address is registered
     * @param ethAddress The ETH address to check
     * @return True if the address is registered
     */
    function isAddressRegistered(address ethAddress) external view returns (bool) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.addressToEpervierKey[ethAddress] != address(0);
    }

    /**
     * @dev Get the PQ fingerprint for a registered ETH address
     * @param ethAddress The ETH address
     * @return The PQ fingerprint (address(0) if not registered)
     */
    function addressToEpervierKey(address ethAddress) external view returns (address) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.addressToEpervierKey[ethAddress];
    }

    /**
     * @dev Get the ETH address for a registered PQ fingerprint
     * @param pqFingerprint The PQ fingerprint
     * @return The ETH address (address(0) if not registered)
     */
    function epervierKeyToAddress(address pqFingerprint) external view returns (address) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.epervierKeyToAddress[pqFingerprint];
    }

    /**
     * @dev Get pending registration intent for an address
     * @param ethAddress The ETH address
     * @return pqFingerprint The PQ fingerprint in the intent
     * @return intentMessage The intent message
     * @return timestamp The timestamp when intent was created
     */
    function pendingIntents(address ethAddress) external view returns (address pqFingerprint, bytes memory intentMessage, uint256 timestamp) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        RegistryStorage.Intent storage intent = s.pendingIntents[ethAddress];
        return (intent.pqFingerprint, intent.intentMessage, intent.timestamp);
    }

    /**
     * @dev Get ETH nonce for an address
     * @param ethAddress The ETH address
     * @return The current nonce
     */
    function ethNonces(address ethAddress) external view returns (uint256) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.ethNonces[ethAddress];
    }

    /**
     * @dev Get PQ key nonce for a fingerprint
     * @param pqFingerprint The PQ fingerprint
     * @return The current nonce
     */
    function pqKeyNonces(address pqFingerprint) external view returns (uint256) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.pqKeyNonces[pqFingerprint];
    }

    /**
     * @dev Get unregistration intent for an address
     * @param ethAddress The ETH address
     * @return timestamp The timestamp when intent was created
     * @return publicKey The public key (2 uint256 array)
     * @return publicKeyAddress The public key address
     */
    function unregistrationIntents(address ethAddress) external view returns (uint256 timestamp, uint256[2] memory publicKey, address publicKeyAddress) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        RegistryStorage.UnregistrationIntent storage intent = s.unregistrationIntents[ethAddress];
        return (intent.timestamp, intent.publicKey, intent.publicKeyAddress);
    }

    /**
     * @dev Get the ETH address that has a pending intent for a PQ fingerprint
     * @param pqFingerprint The PQ fingerprint
     * @return The ETH address with pending intent (address(0) if none)
     */
    function pqFingerprintToPendingIntentAddress(address pqFingerprint) external view returns (address) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.pqFingerprintToPendingIntentAddress[pqFingerprint];
    }

    /**
     * @dev Get change ETH address intent for a PQ fingerprint
     * @param pqFingerprint The PQ fingerprint
     * @return newETHAddress The new ETH address
     * @return oldETHAddress The old ETH address
     * @return timestamp The timestamp when intent was created
     * @return pqNonce The PQ nonce used
     */
    function changeETHAddressIntents(address pqFingerprint) external view returns (address newETHAddress, address oldETHAddress, uint256 timestamp, uint256 pqNonce) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        RegistryStorage.ChangeETHAddressIntent storage intent = s.changeETHAddressIntents[pqFingerprint];
        return (intent.newETHAddress, intent.oldETHAddress, intent.timestamp, intent.pqNonce);
    }

    /**
     * @dev Get the domain separator
     * @return The EIP-712 domain separator
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.DOMAIN_SEPARATOR;
    }

    /**
     * @dev Get the change ETH address intent type hash
     * @return The EIP-712 type hash for change ETH address intent
     */
    function CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("ChangeETHAddressIntent(address newETHAddress,address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the registration confirmation type hash
     * @return The EIP-712 type hash for registration confirmation
     */
    function REGISTRATION_CONFIRMATION_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the remove intent type hash
     * @return The EIP-712 type hash for remove intent
     */
    function REMOVE_INTENT_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("RemoveIntent(address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the change ETH address confirmation type hash
     * @return The EIP-712 type hash for change ETH address confirmation
     */
    function CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("ChangeETHAddressConfirmation(address oldETHAddress,address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the unregistration intent type hash
     * @return The EIP-712 type hash for unregistration intent
     */
    function UNREGISTRATION_INTENT_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("UnregistrationIntent(address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the unregistration confirmation type hash
     * @return The EIP-712 type hash for unregistration confirmation
     */
    function UNREGISTRATION_CONFIRMATION_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("UnregistrationConfirmation(address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the remove change intent type hash
     * @return The EIP-712 type hash for remove change intent
     */
    function REMOVE_CHANGE_INTENT_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("RemoveChangeIntent(address pqFingerprint,uint256 ethNonce)");
    }

    /**
     * @dev Get the remove unregistration intent type hash
     * @return The EIP-712 type hash for remove unregistration intent
     */
    function REMOVE_UNREGISTRATION_INTENT_TYPE_HASH() external pure returns (bytes32) {
        return keccak256("RemoveUnregistrationIntent(uint256 ethNonce)");
    }

    /**
     * @dev Get the Epervier verifier contract
     * @return The Epervier verifier contract interface
     */
    function epervierVerifier() external view returns (IEpervierVerifier) {
        RegistryStorage.Layout storage s = RegistryStorage.layout();
        return s.epervierVerifier;
    }
} 