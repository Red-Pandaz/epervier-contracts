// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MessageValidation
 * @dev Library for validating message patterns and structure
 */
library MessageValidation {
    
    /**
     * @dev Find a pattern in a byte array
     * @param data The data to search in
     * @param pattern The pattern to find
     * @param skipDomainSeparator Whether to skip the first 32 bytes (DOMAIN_SEPARATOR)
     */
    function findPattern(bytes memory data, bytes memory pattern, bool skipDomainSeparator) internal pure returns (uint index) {
        if (pattern.length > data.length) {
            return type(uint).max;
        }
        
        uint startIndex = skipDomainSeparator ? 32 : 0;
        if (startIndex >= data.length) {
            return type(uint).max;
        }
        
        for (uint i = startIndex; i <= data.length - pattern.length; i++) {
            bool found = true;
            for (uint j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        
        return type(uint).max;
    }

    /**
     * @dev Find a pattern in a byte array (backward compatibility)
     */
    function findPattern(bytes memory data, bytes memory pattern) internal pure returns (uint index) {
        return findPattern(data, pattern, false);
    }

    /**
     * @dev Validate that ETH message contains confirmation text for changing ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address" + ethNonce + pqMessage
     */
    function validateETHConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm change ETH Address";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for changing ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing ETH Address from " + currentAddress + " to " + newAddress + pqNonce
     */
    function validatePQConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm changing ETH Address from ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for change ETH Address intent
     * Expected format: DOMAIN_SEPARATOR + "Remove change ETH Address intent" + currentAddress + pqNonce
     */
    function validatePQRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove change ETH Address intent";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + ethNonce + pqMessage
     */
    function validateETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
     */
    function validatePQUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from ETH Address ";
        return findPattern(message, pattern) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for unregistration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce
     */
    function validatePQUnregistrationRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove unregistration intent from ETH Address ";
        uint256 patternIndex = findPattern(message, pattern, true); // Skip DOMAIN_SEPARATOR
        return patternIndex != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for registration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + address + pqNonce
     */
    function validatePQRemoveIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove registration intent from ETH Address ";
        return findPattern(message, pattern) != type(uint).max;
    }
}

