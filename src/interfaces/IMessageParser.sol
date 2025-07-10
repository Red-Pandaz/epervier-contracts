// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IMessageParser
 * @dev Interface for MessageParser contract
 */
interface IMessageParser {
    
    /**
     * @dev Parse a BasePQRegistrationIntentMessage according to our schema
     */
    function parseBasePQRegistrationIntentMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address ethAddress,
        uint256 pqNonce
    );
    
    /**
     * @dev Parse an ETHRegistrationIntentMessage according to our schema
     */
    function parseETHRegistrationIntentMessage(bytes memory message) external pure returns (
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    );
    
    /**
     * @dev Parse a BaseETHRegistrationConfirmationMessage according to our schema
     */
    function parseBaseETHRegistrationConfirmationMessage(bytes memory message) external pure returns (
        address pqFingerprint,
        uint256 ethNonce
    );
    
    /**
     * @dev Parse a PQRegistrationConfirmationMessage according to our schema
     */
    function parsePQRegistrationConfirmationMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address ethAddress,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 pqNonce
    );
    
    /**
     * @dev Parse an ETHRemoveRegistrationIntentMessage according to our schema
     */
    function parseETHRemoveRegistrationIntentMessage(bytes memory message) external pure returns (
        address pqFingerprint,
        uint256 ethNonce
    );
    
    /**
     * @dev Parse an ETHRemoveChangeIntentMessage according to our schema
     */
    function parseETHRemoveChangeIntentMessage(bytes memory message) external pure returns (
        address pqFingerprint,
        uint256 ethNonce
    );
    
    /**
     * @dev Parse a PQChangeETHAddressIntentMessage according to our schema
     */
    function parsePQChangeETHAddressIntentMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    );
    
    /**
     * @dev Parse a BaseETHChangeETHAddressIntentMessage according to our schema
     */
    function parseBaseETHChangeETHAddressIntentMessage(bytes memory message) external pure returns (
        address pqFingerprint,
        address newEthAddress,
        uint256 ethNonce
    );
    
    /**
     * @dev Parse an ETHChangeETHAddressConfirmationMessage according to our schema
     */
    function parseETHChangeETHAddressConfirmationMessage(bytes memory message) external pure returns (
        address pqFingerprint,
        bytes memory basePQMessage,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        uint256 ethNonce
    );
    
    /**
     * @dev Parse a BasePQChangeETHAddressConfirmMessage according to our schema
     */
    function parseBasePQChangeETHAddressConfirmMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce
    );
    
    /**
     * @dev Parse a PQUnregistrationIntentMessage according to our schema
     */
    function parsePQUnregistrationIntentMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address currentEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    );
    
    /**
     * @dev Parse a BaseETHUnregistrationIntentMessage according to our schema
     */
    function parseBaseETHUnregistrationIntentMessage(bytes memory message) external pure returns (
        address ethMessagePqFingerprint,
        uint256 ethNonce
    );
    
    /**
     * @dev Parse a PQRemoveUnregistrationIntentMessage according to our schema
     */
    function parsePQRemoveUnregistrationIntentMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address intentAddress,
        uint256 pqNonce
    );
    
    /**
     * @dev Parse a BasePQUnregistrationConfirmMessage according to our schema
     */
    function parseBasePQUnregistrationConfirmMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address ethAddress,
        uint256 pqNonce
    );
    
    /**
     * @dev Parse an ETHUnregistrationConfirmationMessage according to our schema
     */
    function parseETHUnregistrationConfirmationMessage(bytes memory message) external pure returns (
        address pqFingerprint,
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    );
    
    /**
     * @dev Parse a PQRemoveChangeIntentMessage according to our schema
     */
    function parsePQRemoveChangeIntentMessage(bytes memory message, bytes32 domainSeparator) external pure returns (
        address ethAddress,
        uint256 pqNonce
    );
    
    // Validation functions
    function validateETHRegistrationIntentMessage(bytes memory message) external pure returns (bool);
    function validatePQRegistrationIntentMessage(bytes memory message) external pure returns (bool);
    function validatePQRegistrationConfirmationMessage(bytes memory message) external pure returns (bool);
    function validateBaseETHRegistrationConfirmationMessage(bytes memory message) external pure returns (bool);
    function validateETHRemoveRegistrationIntentMessage(bytes memory message) external pure returns (bool);
    function validateETHRemoveChangeIntentMessage(bytes memory message) external pure returns (bool);
    function validatePQChangeETHAddressIntentMessage(bytes memory message) external pure returns (bool);
    function validateBaseETHChangeETHAddressIntentMessage(bytes memory message) external pure returns (bool);
    function validateETHChangeETHAddressConfirmationMessage(bytes memory message) external pure returns (bool);
    function validateBasePQChangeETHAddressConfirmMessage(bytes memory message) external pure returns (bool);
    function validatePQUnregistrationIntentMessage(bytes memory message) external pure returns (bool);
    function validateBaseETHUnregistrationIntentMessage(bytes memory message) external pure returns (bool);
    function validateETHUnregistrationConfirmationMessage(bytes memory message) external pure returns (bool);
    function validatePQUnregistrationConfirmationMessage(bytes memory message) external pure returns (bool);
    function validatePQUnregistrationRemovalMessage(bytes memory message) external pure returns (bool);
    function validatePQRemoveIntentMessage(bytes memory message) external pure returns (bool);
    function validatePQChangeAddressRemovalMessage(bytes memory message) external pure returns (bool);
    function validateDomainSeparator(bytes memory message, bytes32 domainSeparator) external pure returns (bool);
    
    // Extraction functions
    function extractPQNonceFromRemoveMessage(bytes memory message) external pure returns (uint256);
    function extractEthNonce(bytes memory message, uint8 messageType) external pure returns (uint256);
    function extractPQSalt(bytes memory message, uint8 messageType) external pure returns (bytes memory);
    function extractPQCs1(bytes memory message, uint8 messageType) external pure returns (uint256[] memory);
    function extractPQCs2(bytes memory message, uint8 messageType) external pure returns (uint256[] memory);
    function extractPQHint(bytes memory message, uint8 messageType) external pure returns (uint256);
    function extractBasePQMessage(bytes memory message, uint8 messageType) external pure returns (bytes memory);
    function extractPQNonce(bytes memory message, uint8 messageType) external pure returns (uint256);
    function parseETHAddressFromETHUnregistrationConfirmationMessage(bytes memory message) external pure returns (address);
} 