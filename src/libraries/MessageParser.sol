// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MessageParser
 * @dev Library for parsing various message types in the PQRegistry
 */
library MessageParser {
    
    /**
     * @dev Parse a BasePQRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce
     */
    function parseBasePQRegistrationIntentMessage(bytes memory message) public pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Intent to pair ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59
        fieldOffsets[0] = 59;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 59 + 20 = 79
        fieldOffsets[1] = 79;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert bytes to address and uint256
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse an ETHRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHRegistrationIntentMessage(bytes memory message) internal pure returns (
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Intent to pair Epervier Key";
        uint256[] memory fieldOffsets = new uint256[](6);
        uint256[] memory fieldLengths = new uint256[](6);
        string[] memory fieldTypes = new string[](6);
        
        // basePQMessage: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59, length = 111
        fieldOffsets[0] = 59;
        fieldLengths[0] = 111;
        fieldTypes[0] = "bytes";
        
        // salt: starts after basePQMessage = 59 + 111 = 170, length = 40
        fieldOffsets[1] = 170;
        fieldLengths[1] = 40;
        fieldTypes[1] = "bytes";
        
        // cs1: starts after salt = 170 + 40 = 210, length = 32 * 32 = 1024
        fieldOffsets[2] = 210;
        fieldLengths[2] = 1024;
        fieldTypes[2] = "uint256[32]";
        
        // cs2: starts after cs1 = 210 + 1024 = 1234, length = 32 * 32 = 1024
        fieldOffsets[3] = 1234;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // hint: starts after cs2 = 1234 + 1024 = 2258, length = 32
        fieldOffsets[4] = 2258;
        fieldLengths[4] = 32;
        fieldTypes[4] = "uint256";
        
        // ethNonce: starts after hint = 2258 + 32 = 2290, length = 32
        fieldOffsets[5] = 2290;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        basePQMessage = parsedFields[0];
        salt = parsedFields[1];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[2][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[3][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[4]));
        ethNonce = uint256(bytes32(parsedFields[5]));
    }
    
    /**
     * @dev Parse a BaseETHRegistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function parseBaseETHRegistrationConfirmationMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Confirm bonding to Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (40) = 72
        fieldOffsets[0] = 72;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 72 + 20 = 92
        fieldOffsets[1] = 92;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 40, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRegistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQRegistrationConfirmationMessage(bytes memory message) public pure returns (
        address ethAddress,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm bonding to ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](6);
        uint256[] memory fieldLengths = new uint256[](6);
        string[] memory fieldTypes = new string[](6);
        
        // DOMAIN_SEPARATOR (32 bytes) + pattern (31 bytes) + ethAddress (20 bytes) + baseETHMessage (variable) + v (1 byte) + r (32 bytes) + s (32 bytes) + pqNonce (32 bytes)
        fieldOffsets[0] = 32 + 31; // ethAddress starts after DOMAIN_SEPARATOR + pattern
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // Find the end of baseETHMessage (it's variable length)
        uint256 baseETHMessageStart = fieldOffsets[0] + fieldLengths[0];
        uint256 baseETHMessageLength = message.length - baseETHMessageStart - 1 - 32 - 32 - 32; // - v - r - s - pqNonce
        
        fieldOffsets[1] = baseETHMessageStart;
        fieldLengths[1] = baseETHMessageLength;
        fieldTypes[1] = "bytes";
        
        fieldOffsets[2] = baseETHMessageStart + baseETHMessageLength; // v
        fieldLengths[2] = 1;
        fieldTypes[2] = "uint8";
        
        fieldOffsets[3] = fieldOffsets[2] + fieldLengths[2]; // r
        fieldLengths[3] = 32;
        fieldTypes[3] = "bytes32";
        
        fieldOffsets[4] = fieldOffsets[3] + fieldLengths[3]; // s
        fieldLengths[4] = 32;
        fieldTypes[4] = "bytes32";
        
        fieldOffsets[5] = fieldOffsets[4] + fieldLengths[4]; // pqNonce
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 31, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        baseETHMessage = parsedFields[1];
        v = uint8(parsedFields[2][0]);
        r = bytes32(parsedFields[3]);
        s = bytes32(parsedFields[4]);
        pqNonce = uint256(bytes32(parsedFields[5]));
    }
    
    /**
     * @dev Parse a BasePQUnregistrationConfirmMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
     */
    function parseBasePQUnregistrationConfirmMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm unregistration from ETH Address ";
        
        uint256 manualPatternIndex = type(uint256).max;
        for (uint i = 32; i <= message.length - pattern.length; i++) {
            bool found = true;
            for (uint j = 0; j < pattern.length; j++) {
                if (message[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                manualPatternIndex = i;
                break;
            }
        }
        require(manualPatternIndex != type(uint256).max, "Pattern not found");
        
        // Calculate field offsets
        uint256 ethAddressStart = manualPatternIndex + pattern.length;
        uint256 ethAddressEnd = ethAddressStart + 20;
        uint256 pqNonceStart = ethAddressEnd;
        uint256 pqNonceEnd = pqNonceStart + 32;
        
        require(pqNonceEnd <= message.length, "Message too short for pqNonce");
        
        // Extract ethAddress
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[ethAddressStart + i];
        }
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        ethAddress = address(uint160(addr));
        
        // Extract pqNonce
        bytes memory nonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            nonceBytes[i] = message[pqNonceStart + i];
        }
        pqNonce = uint256(bytes32(nonceBytes));
    }
    
    /**
     * @dev Parse a BaseETHChangeETHAddressIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
     */
    function parseBaseETHChangeETHAddressIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        address newEthAddress,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](4);
        uint256[] memory fieldLengths = new uint256[](4);
        string[] memory fieldTypes = new string[](4);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (64) = 96
        fieldOffsets[0] = 96;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after pqFingerprint = 96 + 20 = 116, length = 4
        fieldOffsets[1] = 116;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 116 + 4 = 120, length = 20
        fieldOffsets[2] = 120;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // ethNonce: starts after newEthAddress = 120 + 20 = 140, length = 32
        fieldOffsets[3] = 140;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 64, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to addresses manually to ensure correct byte order
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr1));
        
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(parsedFields[2][j]);
        }
        newEthAddress = address(uint160(addr2));
        ethNonce = uint256(bytes32(parsedFields[3]));
    }
    
    /**
     * @dev Parse a PQChangeETHAddressIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQChangeETHAddressIntentMessage(bytes memory message) internal pure returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        bytes memory pattern = "Intent to change bound ETH Address from ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // oldEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (40) = 72
        fieldOffsets[0] = 72;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 72 + 20 = 92, length = 4
        fieldOffsets[1] = 92;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 92 + 4 = 96, length = 20
        fieldOffsets[2] = 96;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // baseETHMessage: starts after newEthAddress = 96 + 20 = 116, length = 172
        fieldOffsets[3] = 116;
        fieldLengths[3] = 172;
        fieldTypes[3] = "bytes";
        
        // v: starts after baseETHMessage = 116 + 172 = 288, length = 1
        fieldOffsets[4] = 288;
        fieldLengths[4] = 1;
        fieldTypes[4] = "uint8";
        
        // r: starts after v = 288 + 1 = 289, length = 32
        fieldOffsets[5] = 289;
        fieldLengths[5] = 32;
        fieldTypes[5] = "bytes32";
        
        // s: starts after r = 289 + 32 = 321, length = 32
        fieldOffsets[6] = 321;
        fieldLengths[6] = 32;
        fieldTypes[6] = "bytes32";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 40, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to addresses manually to ensure correct byte order
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(parsedFields[0][j]);
        }
        oldEthAddress = address(uint160(addr1));
        
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(parsedFields[2][j]);
        }
        newEthAddress = address(uint160(addr2));
        
        baseETHMessage = parsedFields[3];
        v = uint8(parsedFields[4][0]);
        r = bytes32(parsedFields[5]);
        s = bytes32(parsedFields[6]);
        
        // Extract pqNonce from the end of the message (last 32 bytes)
        bytes memory pqNonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            pqNonceBytes[j] = message[message.length - 32 + j];
        }
        pqNonce = uint256(bytes32(pqNonceBytes));
    }
    
    /**
     * @dev Parse a BasePQChangeETHAddressConfirmMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing bound ETH Address for Epervier Fingerprint from " + oldEthAddress + " to " + newEthAddress + pqNonce
     */
    function parseBasePQChangeETHAddressConfirmMessage(bytes memory message) internal pure returns (
        address oldEthAddress,
        address newEthAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Confirm changing bound ETH Address for Epervier Fingerprint from ";
        uint256[] memory fieldOffsets = new uint256[](4);
        uint256[] memory fieldLengths = new uint256[](4);
        string[] memory fieldTypes = new string[](4);
        
        // oldEthAddress: starts after DOMAIN_SEPARATOR (32) + pattern (65) = 97
        fieldOffsets[0] = 97;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 97 + 20 = 117, length = 4
        fieldOffsets[1] = 117;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 117 + 4 = 121, length = 20
        fieldOffsets[2] = 121;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // pqNonce: starts after newEthAddress = 121 + 20 = 141, length = 32
        fieldOffsets[3] = 141;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 65, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to addresses manually to ensure correct byte order
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(parsedFields[0][j]);
        }
        oldEthAddress = address(uint160(addr1));
        
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(parsedFields[2][j]);
        }
        newEthAddress = address(uint160(addr2));
        pqNonce = uint256(bytes32(parsedFields[3]));
    }
    
    /**
     * @dev Parse a BaseETHUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from PQ fingerprint" + pqFingerprint + ethNonce
     */
    function parseBaseETHUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to unregister from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (47) = 79
        fieldOffsets[0] = 79;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 79 + 20 = 99
        fieldOffsets[1] = 99;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function parsePQUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address currentEthAddress,
        uint256 pqNonce,
        bytes memory baseETHMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        // Schema-based offsets (from pqregistry_message_schema.json)
        // DOMAIN_SEPARATOR: 32 bytes
        // pattern: 60 bytes ("Intent to unregister from Epervier Fingerprint from address ")
        // currentEthAddress: 20 bytes (offset 92)
        // baseETHMessage: 131 bytes (offset 112)
        // v: 1 byte (offset 243)
        // r: 32 bytes (offset 244)
        // s: 32 bytes (offset 276)
        // pqNonce: 32 bytes (offset 308)
        
        require(message.length >= 340, "Message too short for PQUnregistrationIntentMessage");
        
        // Extract ETH address (offset 92, length 20)
        bytes memory addrBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addrBytes[i] = message[92 + i];
        }
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addrBytes[j]);
        }
        currentEthAddress = address(uint160(addr));
        
        // Extract baseETHMessage (offset 112, length 131)
        baseETHMessage = new bytes(131);
        for (uint i = 0; i < 131; i++) {
            baseETHMessage[i] = message[112 + i];
        }
        
        // Extract v (offset 243, length 1)
        v = uint8(message[243]);
        
        // Extract r (offset 244, length 32)
        bytes memory rBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            rBytes[i] = message[244 + i];
        }
        r = bytes32(rBytes);
        
        // Extract s (offset 276, length 32)
        bytes memory sBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            sBytes[i] = message[276 + i];
        }
        s = bytes32(sBytes);
        
        // Extract pqNonce (offset 308, length 32)
        bytes memory nonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            nonceBytes[i] = message[308 + i];
        }
        pqNonce = uint256(bytes32(nonceBytes));
    }
    
    /**
     * @dev Parse an ETHUnregistrationConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (49) = 81
        fieldOffsets[0] = 81;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 81 + 20 = 101, length = 111
        fieldOffsets[1] = 101;
        fieldLengths[1] = 111;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 101 + 111 = 212, length = 40
        fieldOffsets[2] = 212;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 212 + 40 = 252, length = 32 * 32 = 1024
        fieldOffsets[3] = 252;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 252 + 1024 = 1276, length = 32 * 32 = 1024
        fieldOffsets[4] = 1276;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1276 + 1024 = 2300, length = 32
        fieldOffsets[5] = 2300;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2300 + 32 = 2332, length = 32
        fieldOffsets[6] = 2332;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 49, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        basePQMessage = parsedFields[1];
        salt = parsedFields[2];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[3][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[4][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[5]));
        ethNonce = uint256(bytes32(parsedFields[6]));
    }
    
    /**
     * @dev Parse an ETHChangeETHAddressConfirmationMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address for Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHChangeETHAddressConfirmationMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Confirm change ETH Address for Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (52) = 84
        fieldOffsets[0] = 84;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 84 + 20 = 104, length = 173
        fieldOffsets[1] = 104;
        fieldLengths[1] = 173;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 104 + 173 = 277, length = 40
        fieldOffsets[2] = 277;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 277 + 40 = 317, length = 32 * 32 = 1024
        fieldOffsets[3] = 317;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 317 + 1024 = 1341, length = 32 * 32 = 1024
        fieldOffsets[4] = 1341;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1341 + 1024 = 2365, length = 32
        fieldOffsets[5] = 2365;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2365 + 32 = 2397, length = 32
        fieldOffsets[6] = 2397;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 52, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        
        basePQMessage = parsedFields[1];
        salt = parsedFields[2];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[3][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[4][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[5]));
        ethNonce = uint256(bytes32(parsedFields[6]));
    }
    
    /**
     * @dev Parse ETH Address from ETH unregistration confirmation message
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + fingerprintAddress + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHAddressFromETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (address fingerprintAddress) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        uint startOffset = 32; // Skip DOMAIN_SEPARATOR
        uint patternIndex = findPattern(message, pattern, true); // true = skip DOMAIN_SEPARATOR
        if (patternIndex == type(uint).max) {
            return address(0);
        }
        uint addressStart = patternIndex + pattern.length;
        if (addressStart + 20 > message.length) {
            return address(0);
        }
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[addressStart + i];
        }
        // Manual conversion to address (big-endian)
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        return address(uint160(addr));
    }
    
    /**
     * @dev Extract ETH nonce from a message according to schema
     * For intent messages: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ... + ethNonce (last 32 bytes)
     * For confirmation messages: DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + ... + ethNonce (last 32 bytes)
     * @param message The message to extract nonce from
     * @param messageType 0 for intent message, 1 for confirmation message
     */
    function extractEthNonce(bytes memory message, uint8 messageType) internal pure returns (uint256 ethNonce) {
        if (messageType == 0) {
            // Intent message: ETH nonce is the last 32 bytes
            require(message.length >= 32, "Message too short for ETH nonce");
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else if (messageType == 1) {
            // Confirmation message: ETH nonce is the last 32 bytes
            require(message.length >= 32, "Message too short for ETH nonce");
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else if (messageType == 2) {
            // Unregistration confirmation message: ETH nonce is the last 32 bytes
            require(message.length >= 32, "Message too short for ETH nonce");
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else {
            revert("Invalid message type");
        }
    }
    
    /**
     * @dev Unified message parser that can handle all message types from our schema
     * @param message The message to parse
     * @param expectedPattern The expected pattern to find in the message
     * @param patternLength The length of the expected pattern
     * @param fieldOffsets Array of field offsets from the start of the message
     * @param fieldLengths Array of field lengths
     * @param fieldTypes Array of field types ("address", "uint256", "bytes", "uint8", "bytes32")
     * @return parsedFields Array of parsed field values as bytes
     */
    function parseMessageFields(
        bytes memory message,
        bytes memory expectedPattern,
        uint256 patternLength,
        uint256[] memory fieldOffsets,
        uint256[] memory fieldLengths,
        string[] memory fieldTypes
    ) internal pure returns (bytes[] memory parsedFields) {
        require(fieldOffsets.length == fieldLengths.length, "Field offsets and lengths must match");
        require(fieldOffsets.length == fieldTypes.length, "Field offsets and types must match");
        
        uint256 patternIndex = findPattern(message, expectedPattern, true); // Skip DOMAIN_SEPARATOR
        
        // Debug: If pattern not found, we can't emit events from a pure function
        // But we can encode the debug info in the revert message
        if (patternIndex == type(uint256).max) {
            // Create a debug message with pattern and message info
            string memory debugInfo = string(abi.encodePacked(
                "Pattern not found. Expected: '",
                string(expectedPattern),
                "' (length: ",
                uint2str(expectedPattern.length),
                "). Message length: ",
                uint2str(message.length),
                ". Message starts with: '",
                bytesToString(message, 0, 50), // Show first 50 bytes as string
                "'"
            ));
            revert(debugInfo);
        }
        
        require(patternIndex != type(uint256).max, "Expected pattern not found in message");
        
        parsedFields = new bytes[](fieldOffsets.length);
        for (uint256 i = 0; i < fieldOffsets.length; i++) {
            uint256 actualFieldStart = patternIndex + patternLength + (fieldOffsets[i] - (32 + patternLength));
            uint256 fieldLength = fieldLengths[i];
            require(actualFieldStart + fieldLength <= message.length, "Field extends beyond message length");
            parsedFields[i] = new bytes(fieldLength);
            for (uint256 j = 0; j < fieldLength; j++) {
                parsedFields[i][j] = message[actualFieldStart + j];
            }
        }
        return parsedFields;
    }
    
    /**
     * @dev Helper function to convert uint to string
     */
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        while (_i != 0) {
            k -= 1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
    
    /**
     * @dev Helper function to convert bytes to string (for debug)
     */
    function bytesToString(bytes memory data, uint256 start, uint256 length) internal pure returns (string memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length && start + i < data.length; i++) {
            result[i] = data[start + i];
        }
        return string(result);
    }
    
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
     * @dev Parse an ETHRemoveRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function parseETHRemoveRegistrationIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove registration intent from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (53) = 85
        fieldOffsets[0] = 85;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 85 + 20 = 105
        fieldOffsets[1] = 105;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 53, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse an ETHRemoveChangeIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function parseETHRemoveChangeIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Remove change intent from Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (47) = 79
        fieldOffsets[0] = 79;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 79 + 20 = 99
        fieldOffsets[1] = 99;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        pqFingerprint = address(uint160(addr));
        ethNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveRegistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + ethAddress + pqNonce
     */
    function parsePQRemoveRegistrationIntentMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove registration intent from ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (44) = 76
        fieldOffsets[0] = 76;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        // pqNonce: starts after ethAddress = 76 + 20 = 96
        fieldOffsets[1] = 96;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 44, fieldOffsets, fieldLengths, fieldTypes);
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveChangeIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
     */
    function parsePQRemoveChangeIntentMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove change intent from ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (38) = 70
        fieldOffsets[0] = 70;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 70 + 20 = 90
        fieldOffsets[1] = 90;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 38, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a PQRemoveUnregistrationIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce
     */
    function parsePQRemoveUnregistrationIntentMessage(bytes memory message) internal pure returns (
        address ethAddress,
        uint256 pqNonce
    ) {
        bytes memory pattern = "Remove unregistration intent from ETH Address ";
        uint256[] memory fieldOffsets = new uint256[](2);
        uint256[] memory fieldLengths = new uint256[](2);
        string[] memory fieldTypes = new string[](2);
        
        // ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (46) = 78
        fieldOffsets[0] = 78;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 78 + 20 = 98
        fieldOffsets[1] = 98;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 46, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert the extracted bytes to address manually to ensure correct byte order
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(parsedFields[0][j]);
        }
        ethAddress = address(uint160(addr));
        pqNonce = uint256(bytes32(parsedFields[1]));
    }
    
    /**
     * @dev Parse a ETHChangeETHAddressIntentMessage according to our schema
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function parseETHChangeETHAddressIntentMessage(bytes memory message) internal pure returns (
        uint256 ethNonce,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        bytes memory basePQMessage
    ) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        uint256[] memory fieldOffsets = new uint256[](7);
        uint256[] memory fieldLengths = new uint256[](7);
        string[] memory fieldTypes = new string[](7);
        
        // pqFingerprint: starts after DOMAIN_SEPARATOR (32) + pattern (52) = 84
        fieldOffsets[0] = 84;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 84 + 20 = 104, length = 173
        fieldOffsets[1] = 104;
        fieldLengths[1] = 173;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 104 + 173 = 277, length = 40
        fieldOffsets[2] = 277;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 277 + 40 = 317, length = 32 * 32 = 1024
        fieldOffsets[3] = 317;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 317 + 1024 = 1341, length = 32 * 32 = 1024
        fieldOffsets[4] = 1341;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1341 + 1024 = 2365, length = 32
        fieldOffsets[5] = 2365;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2365 + 32 = 2397, length = 32
        fieldOffsets[6] = 2397;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 52, fieldOffsets, fieldLengths, fieldTypes);
        
        // Convert parsed fields to appropriate types
        // Note: pqFingerprint is parsed but not returned as it's not needed for this function
        basePQMessage = parsedFields[1];
        salt = parsedFields[2];
        
        // Convert cs1 bytes to uint256 array
        cs1 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs1Element[j] = parsedFields[3][i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        // Convert cs2 bytes to uint256 array
        cs2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint256 j = 0; j < 32; j++) {
                cs2Element[j] = parsedFields[4][i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        hint = uint256(bytes32(parsedFields[5]));
        ethNonce = uint256(bytes32(parsedFields[6]));
    }
    
    /**
     * @dev Extract PQ nonce from message
     * @param message The message to extract nonce from
     * @param messageType 0 for intent message, 1 for confirmation message
     * Intent format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
     * Confirmation format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce + ethSignature + ETH_message
     */
    function extractPQNonce(bytes memory message, uint8 messageType) internal pure returns (uint256 pqNonce) {
        if (messageType == 0) {
            // Intent message format - PQ nonce is at the end
            require(message.length >= 32 + 27 + 20 + 32, "Message too short for PQ nonce from intent message");
            
            // Extract the last 32 bytes as the PQ nonce
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j];
            }
            return abi.decode(nonceBytes, (uint256));
        } else if (messageType == 1) {
            // Confirmation message format
            require(message.length >= 32 + 40 + 20 + 32, "Message too short for ETH nonce from confirmation message");
            
            // Extract the ETH nonce (last 32 bytes of the message)
            bytes memory nonceBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                nonceBytes[j] = message[message.length - 32 + j]; // Last 32 bytes
            }
            return abi.decode(nonceBytes, (uint256));
        } else {
            revert("Invalid message type");
        }
    }
    
    /**
     * @dev Extract PQ nonce from remove intent message
     * Expected format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
     */
    function extractPQNonceFromRemoveMessage(bytes memory message) internal pure returns (uint256 pqNonce) {
        require(message.length >= 32 + 44 + 20 + 32, "Message too short for PQ nonce from remove message");
        
        // Extract the PQ nonce (last 32 bytes of the message)
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[message.length - 32 + j];
        }
        return abi.decode(nonceBytes, (uint256));
    }
    
    /**
     * @dev Validate that ETH message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function validateETHUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
     */
    function validatePQUnregistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm unregistration from ETH Address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for unregistration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce
     */
    function validatePQUnregistrationRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove unregistration intent from ETH Address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for registration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + address + pqNonce
     */
    function validatePQRemoveIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove registration intent from ETH Address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains removal text for change ETH Address intent
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
     */
    function validatePQChangeAddressRemovalMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove change intent from ETH Address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains intent text for registration
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function validateETHRegistrationIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to pair Epervier Key";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains intent text for registration
     * Expected format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce
     */
    function validatePQRegistrationIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to pair ETH Address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains confirmation text for registration
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function validateETHRegistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm bonding to Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for registration
     * Expected format: DOMAIN_SEPARATOR + "Confirm bonding to ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce
     */
    function validatePQRegistrationConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm bonding to ETH Address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains removal text for registration intent
     * Expected format: DOMAIN_SEPARATOR + "Remove registration intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function validateETHRemoveRegistrationIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove registration intent from Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains intent text for change ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
     */
    function validateETHChangeETHAddressIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains intent text for change ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function validatePQChangeETHAddressIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to change bound ETH Address from ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains confirmation text for change ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Confirm changing bound ETH Address for Epervier Fingerprint from " + oldEthAddress + " to " + newEthAddress + pqNonce
     */
    function validatePQChangeETHAddressConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm changing bound ETH Address for Epervier Fingerprint from ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains confirmation text for change ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Confirm change ETH Address for Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     */
    function validateETHChangeETHAddressConfirmationMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Confirm change ETH Address for Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains removal text for change ETH Address intent
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function validateETHRemoveChangeIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove change intent from Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains intent text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function validateETHUnregistrationIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to unregister from Epervier Fingerprint ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Validate that PQ message contains intent text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
     */
    function validatePQUnregistrationIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to unregister from Epervier Fingerprint from address ";
        return findPattern(message, pattern, true) != type(uint).max;
    }

    /**
     * @dev Extract PQ signature salt from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     * Registration format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     * ChangeETHAddress format: DOMAIN_SEPARATOR + "Confirm change ETH Address" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     * Unregistration format: DOMAIN_SEPARATOR + "Confirm unregistration" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
     */
    function extractPQSalt(bytes memory message, uint8 messageType) internal pure returns (bytes memory salt) {
        uint256 patternLength;
        if (messageType == 0) {
            // Registration: "Intent to pair Epervier Key" (27 bytes)
            patternLength = 27;
        } else if (messageType == 1) {
            // ChangeETHAddress: "Intent to change ETH Address and bond with Epervier Fingerprint " (64 bytes)
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt
        require(message.length >= 32 + patternLength + 32 + 40, "Message too short for PQ salt");
        
        // Extract the salt (40 bytes after DOMAIN_SEPARATOR + pattern + ethNonce)
        bytes memory saltBytes = new bytes(40);
        for (uint j = 0; j < 40; j++) {
            saltBytes[j] = message[32 + patternLength + 32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + offset
        }
        return saltBytes;
    }

    /**
     * @dev Extract PQ signature cs1 from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractPQCs1(bytes memory message, uint8 messageType) internal pure returns (uint256[] memory cs1) {
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32, "Message too short for PQ cs1");
        
        // Extract cs1 (32 uint256 values after salt)
        cs1 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs1Bytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs1Bytes[j] = message[32 + patternLength + 32 + 40 + i*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + offset
            }
            cs1[i] = abi.decode(cs1Bytes, (uint256));
        }
        return cs1;
    }

    /**
     * @dev Extract PQ signature cs2 from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractPQCs2(bytes memory message, uint8 messageType) internal pure returns (uint256[] memory cs2) {
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32 + 32*32, "Message too short for PQ cs2");
        
        // Extract cs2 (32 uint256 values after cs1)
        cs2 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs2Bytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs2Bytes[j] = message[32 + patternLength + 32 + 40 + 32*32 + i*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + offset
            }
            cs2[i] = abi.decode(cs2Bytes, (uint256));
        }
        return cs2;
    }

    /**
     * @dev Extract PQ signature hint from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractPQHint(bytes memory message, uint8 messageType) internal pure returns (uint256 hint) {
        uint256 patternLength;
        if (messageType == 0) {
            patternLength = 27;
        } else if (messageType == 1) {
            patternLength = 64;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            patternLength = 49;
        } else {
            revert("Invalid message type");
        }
        
        // Check if message is long enough to contain the pattern + ethNonce + salt + cs1 + cs2 + hint
        require(message.length >= 32 + patternLength + 32 + 40 + 32*32 + 32*32 + 32, "Message too short for PQ hint");
        
        // Extract hint (32 bytes after cs2)
        bytes memory hintBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            hintBytes[j] = message[32 + patternLength + 32 + 40 + 32*32 + 32*32 + j]; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + cs2 + offset
        }
        hint = abi.decode(hintBytes, (uint256));
        
        return hint;
    }

    /**
     * @dev Extract base PQ message from ETH message
     * @param messageType 0=Registration, 1=ChangeETHAddress, 2=Unregistration
     */
    function extractBasePQMessage(bytes memory message, uint8 messageType) internal pure returns (bytes memory basePQMessage) {
        if (messageType == 0) {
            // Registration: "Intent to pair Epervier Key" (27 bytes)
            // Format: DOMAIN_SEPARATOR + pattern + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
            uint256 patternLength = 27;
            uint256 baseMessageStart = 32 + patternLength; // DOMAIN_SEPARATOR + pattern
            uint256 baseMessageLength = 111; // BasePQRegistrationIntentMessage length
            
            require(message.length >= baseMessageStart + baseMessageLength, "Message too short for base PQ message");
            
            basePQMessage = new bytes(baseMessageLength);
            for (uint j = 0; j < baseMessageLength; j++) {
                basePQMessage[j] = message[baseMessageStart + j];
            }
            return basePQMessage;
        } else if (messageType == 1) {
            // ChangeETHAddress: "Confirm change ETH Address for Epervier Fingerprint " (52 bytes)
            // Format: DOMAIN_SEPARATOR + pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
            uint256 patternLength = 52;
            uint256 baseMessageStart = 32 + patternLength + 20; // DOMAIN_SEPARATOR + pattern + pqFingerprint
            uint256 baseMessageLength = 173; // BasePQChangeETHAddressConfirmMessage length
            
            require(message.length >= baseMessageStart + baseMessageLength, "Message too short for base PQ message");
            
            basePQMessage = new bytes(baseMessageLength);
            for (uint j = 0; j < baseMessageLength; j++) {
                basePQMessage[j] = message[baseMessageStart + j];
            }
            return basePQMessage;
        } else if (messageType == 2) {
            // Unregistration: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
            // Format: DOMAIN_SEPARATOR + pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
            uint256 patternLength = 49;
            uint256 baseMessageStart = 32 + patternLength + 20; // DOMAIN_SEPARATOR + pattern + pqFingerprint
            uint256 baseMessageLength = 124; // BasePQUnregistrationConfirmMessage length (updated from 123 to 124)
            require(baseMessageStart + baseMessageLength <= message.length, "Message too short for base PQ message");
            basePQMessage = new bytes(baseMessageLength);
            for (uint i = 0; i < baseMessageLength; i++) {
                basePQMessage[i] = message[baseMessageStart + i];
            }
        } else {
            revert("Invalid message type");
        }
    }
}
