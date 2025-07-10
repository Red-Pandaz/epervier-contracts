// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IMessageValidation
 * @dev Interface for MessageValidation contract
 */
interface IMessageValidation {
    
    /**
     * @dev Find a pattern in a byte array
     * @param data The data to search in
     * @param pattern The pattern to find
     * @param skipDomainSeparator Whether to skip the first 32 bytes (DOMAIN_SEPARATOR)
     */
    function findPattern(bytes memory data, bytes memory pattern, bool skipDomainSeparator) external pure returns (uint index);
    
    /**
     * @dev Find a pattern in a byte array (backward compatibility)
     */
    function findPattern(bytes memory data, bytes memory pattern) external pure returns (uint index);
    
    /**
     * @dev Validate that ETH message contains confirmation text for changing ETH Address
     */
    function validateETHConfirmationMessage(bytes memory message) external pure returns (bool);
    
    /**
     * @dev Validate that PQ message contains confirmation text for changing ETH Address
     */
    function validatePQConfirmationMessage(bytes memory message) external pure returns (bool);
    
    /**
     * @dev Validate that PQ message contains removal text for change ETH Address intent
     */
    function validatePQRemovalMessage(bytes memory message) external pure returns (bool);
    
    /**
     * @dev Validate that ETH message contains confirmation text for unregistration
     */
    function validateETHUnregistrationConfirmationMessage(bytes memory message) external pure returns (bool);
    
    /**
     * @dev Validate that PQ message contains confirmation text for unregistration
     */
    function validatePQUnregistrationConfirmationMessage(bytes memory message) external pure returns (bool);
    
    /**
     * @dev Validate that PQ message contains removal text for unregistration intent
     */
    function validatePQUnregistrationRemovalMessage(bytes memory message) external pure returns (bool);
    
    /**
     * @dev Validate that PQ message contains removal text for registration intent
     */
    function validatePQRemoveIntentMessage(bytes memory message) external pure returns (bool);
} 