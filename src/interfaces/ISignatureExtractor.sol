// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ISignatureExtractor
 * @dev Interface for SignatureExtractor contract
 */
interface ISignatureExtractor {
    
    // EIP-712 Type Hashes
    function REGISTRATION_INTENT_TYPE_HASH() external pure returns (bytes32);
    function REGISTRATION_CONFIRMATION_TYPE_HASH() external pure returns (bytes32);
    function REMOVE_INTENT_TYPE_HASH() external pure returns (bytes32);
    function CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH() external pure returns (bytes32);
    function CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH() external pure returns (bytes32);
    function UNREGISTRATION_INTENT_TYPE_HASH() external pure returns (bytes32);
    function UNREGISTRATION_CONFIRMATION_TYPE_HASH() external pure returns (bytes32);
    function REMOVE_CHANGE_INTENT_TYPE_HASH() external pure returns (bytes32);
    function REMOVE_UNREGISTRATION_INTENT_TYPE_HASH() external pure returns (bytes32);
    
    /**
     * @dev Extract ETH signature from PQ message
     */
    function extractETHSignature(bytes memory message) external pure returns (bytes memory ethSignature);
    
    /**
     * @dev Extract PQ signature salt from ETH message
     */
    function extractPQSalt(bytes memory message, uint8 messageType) external pure returns (bytes memory salt);
    
    /**
     * @dev Extract PQ signature cs1 from ETH message
     */
    function extractPQCs1(bytes memory message, uint8 messageType) external pure returns (uint256[] memory cs1);
    
    /**
     * @dev Extract PQ signature cs2 from ETH message
     */
    function extractPQCs2(bytes memory message, uint8 messageType) external pure returns (uint256[] memory cs2);
    
    /**
     * @dev Extract PQ signature hint from ETH message
     */
    function extractPQHint(bytes memory message, uint8 messageType) external pure returns (uint256 hint);
    
    /**
     * @dev Extract base PQ message from ETH message
     */
    function extractBasePQMessage(bytes memory message, uint8 messageType) external pure returns (bytes memory basePQMessage);
    
    /**
     * @dev Get EIP-712 digest
     */
    function getEIP712Digest(bytes32 domainSeparator, bytes32 structHash) external pure returns (bytes32);
    
    /**
     * @dev Get registration intent struct hash
     */
    function getRegistrationIntentStructHash(
        bytes memory salt,
        uint256[32] memory cs1,
        uint256[32] memory cs2,
        uint256 hint,
        bytes memory basePQMessage,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get registration confirmation struct hash
     */
    function getRegistrationConfirmationStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get remove intent struct hash
     */
    function getRemoveIntentStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get remove change intent struct hash
     */
    function getRemoveChangeIntentStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get change ETH address intent struct hash
     */
    function getChangeETHAddressIntentStructHash(
        address newETHAddress,
        address pqFingerprint,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get change ETH address confirmation struct hash
     */
    function getChangeETHAddressConfirmationStructHash(
        address oldETHAddress,
        address pqFingerprint,
        bytes memory basePQMessage,
        bytes memory salt,
        uint256[32] memory cs1,
        uint256[32] memory cs2,
        uint256 hint,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get unregistration intent struct hash
     */
    function getUnregistrationIntentStructHash(
        address pqFingerprint,
        uint256 ethNonce
    ) external pure returns (bytes32);
    
    /**
     * @dev Get unregistration confirmation struct hash
     */
    function getUnregistrationConfirmationStructHash(
        address pqFingerprint,
        bytes memory basePQMessage,
        bytes memory salt,
        uint256[32] memory cs1,
        uint256[32] memory cs2,
        uint256 hint,
        uint256 ethNonce
    ) external pure returns (bytes32);
} 