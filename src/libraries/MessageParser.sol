// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/console.sol";

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
        
        // ethAddress: starts after pattern (27) = 27
        fieldOffsets[0] = 27;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 27 + 20 = 47
        fieldOffsets[1] = 47;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes, true);
        
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
        
        // basePQMessage: starts after pattern (27) = 27, length = 111
        fieldOffsets[0] = 27;
        fieldLengths[0] = 111;
        fieldTypes[0] = "bytes";
        
        // salt: starts after basePQMessage = 27 + 111 = 138, length = 40
        fieldOffsets[1] = 138;
        fieldLengths[1] = 40;
        fieldTypes[1] = "bytes";
        
        // cs1: starts after salt = 138 + 40 = 178, length = 32 * 32 = 1024
        fieldOffsets[2] = 178;
        fieldLengths[2] = 1024;
        fieldTypes[2] = "uint256[32]";
        
        // cs2: starts after cs1 = 178 + 1024 = 1202, length = 32 * 32 = 1024
        fieldOffsets[3] = 1202;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // hint: starts after cs2 = 1202 + 1024 = 2226, length = 32
        fieldOffsets[4] = 2226;
        fieldLengths[4] = 32;
        fieldTypes[4] = "uint256";
        
        // ethNonce: starts after hint = 2226 + 32 = 2258, length = 32
        fieldOffsets[5] = 2258;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 27, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        
        // pqFingerprint: starts after pattern (40) = 40
        fieldOffsets[0] = 40;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 40 + 20 = 60
        fieldOffsets[1] = 60;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 40, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        // According to schema:
        // DOMAIN_SEPARATOR (32) + pattern (31) + ethAddress (20) + baseETHMessage (92) + v (1) + r (32) + s (32) + pqNonce (32)
        bytes memory pattern = "Confirm bonding to ETH Address ";
        uint256 patternOffset = 32; // DOMAIN_SEPARATOR is 32 bytes
        uint256 ethAddressOffset = patternOffset + pattern.length;
        uint256 baseETHMessageOffset = ethAddressOffset + 20;
        uint256 vOffset = baseETHMessageOffset + 92;
        uint256 rOffset = vOffset + 1;
        uint256 sOffset = rOffset + 32;
        uint256 pqNonceOffset = sOffset + 32;

        require(message.length >= pqNonceOffset + 32, "Message too short for PQ confirmation");

        // Find the pattern at the expected position
        for (uint i = 0; i < pattern.length; i++) {
            require(message[patternOffset + i] == pattern[i], "Pattern mismatch in PQ confirmation");
        }

        // Extract ethAddress
        bytes memory addressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = message[ethAddressOffset + i];
        }
        uint256 addr = 0;
        for (uint j = 0; j < 20; j++) {
            addr = (addr << 8) | uint8(addressBytes[j]);
        }
        ethAddress = address(uint160(addr));

        // Extract baseETHMessage
        baseETHMessage = new bytes(92);
        for (uint i = 0; i < 92; i++) {
            baseETHMessage[i] = message[baseETHMessageOffset + i];
        }

        // Extract v
        v = uint8(message[vOffset]);

        // Extract r
        bytes memory rBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            rBytes[i] = message[rOffset + i];
        }
        r = bytes32(rBytes);

        // Extract s
        bytes memory sBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            sBytes[i] = message[sOffset + i];
        }
        s = bytes32(sBytes);

        // Extract pqNonce
        bytes memory pqNonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            pqNonceBytes[i] = message[pqNonceOffset + i];
        }
        pqNonce = uint256(bytes32(pqNonceBytes));
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
        for (uint i = 0; i <= message.length - pattern.length; i++) {
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
     * Expected format: "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
     */
    function parseBaseETHChangeETHAddressIntentMessage(bytes memory message) internal pure returns (
        address pqFingerprint,
        address newEthAddress,
        uint256 ethNonce
    ) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        
        uint256 manualPatternIndex = type(uint256).max;
        for (uint i = 0; i <= message.length - pattern.length; i++) {
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
        
        // Calculate field offsets relative to pattern start
        uint256 pqFingerprintStart = manualPatternIndex + pattern.length;
        uint256 pqFingerprintEnd = pqFingerprintStart + 20;
        uint256 toPatternStart = pqFingerprintEnd;
        uint256 toPatternEnd = toPatternStart + 4;
        uint256 newEthAddressStart = toPatternEnd;
        uint256 newEthAddressEnd = newEthAddressStart + 20;
        uint256 ethNonceStart = newEthAddressEnd;
        uint256 ethNonceEnd = ethNonceStart + 32;
        
        require(ethNonceEnd <= message.length, "Message too short for ethNonce");
        
        // Extract pqFingerprint
        bytes memory pqFingerprintBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            pqFingerprintBytes[i] = message[pqFingerprintStart + i];
        }
        uint256 addr1 = 0;
        for (uint j = 0; j < 20; j++) {
            addr1 = (addr1 << 8) | uint8(pqFingerprintBytes[j]);
        }
        pqFingerprint = address(uint160(addr1));
        
        // Extract newEthAddress
        bytes memory newEthAddressBytes = new bytes(20);
        for (uint i = 0; i < 20; i++) {
            newEthAddressBytes[i] = message[newEthAddressStart + i];
        }
        uint256 addr2 = 0;
        for (uint j = 0; j < 20; j++) {
            addr2 = (addr2 << 8) | uint8(newEthAddressBytes[j]);
        }
        newEthAddress = address(uint160(addr2));
        
        // Debug logging
        console.log("DEBUG: Pattern found at index:", manualPatternIndex);
        console.log("DEBUG: Pattern length:", pattern.length);
        console.log("DEBUG: pqFingerprintStart:", pqFingerprintStart);
        console.log("DEBUG: pqFingerprintEnd:", pqFingerprintEnd);
        console.log("DEBUG: toPatternStart:", toPatternStart);
        console.log("DEBUG: toPatternEnd:", toPatternEnd);
        console.log("DEBUG: newEthAddressStart:", newEthAddressStart);
        console.log("DEBUG: newEthAddressEnd:", newEthAddressEnd);
        
        // Print the actual bytes being read
        console.log("DEBUG: Message length:", message.length);
        console.log("DEBUG: Bytes at newEthAddressStart:");
        for (uint i = 0; i < 20; i++) {
            console.log("DEBUG: Byte", i, ":", uint8(message[newEthAddressStart + i]));
        }
        
        console.log("DEBUG: newEthAddressBytes (hex):", uint256(uint160(newEthAddress)));
        console.log("DEBUG: Expected Bob's address:", uint256(uint160(0x70997970C51812dc3A010C7d01b50e0d17dc79C8)));
        console.log("DEBUG: Extracted newEthAddress:", uint256(uint160(newEthAddress)));
        
        // Extract ethNonce
        bytes memory ethNonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            ethNonceBytes[i] = message[ethNonceStart + i];
        }
        ethNonce = uint256(bytes32(ethNonceBytes));
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
        
        // oldEthAddress: starts after pattern (40) = 40
        fieldOffsets[0] = 40;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 40 + 20 = 60, length = 4
        fieldOffsets[1] = 60;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 60 + 4 = 64, length = 20
        fieldOffsets[2] = 64;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // baseETHMessage: starts after newEthAddress = 64 + 20 = 84, length = 140
        fieldOffsets[3] = 84;
        fieldLengths[3] = 140;
        fieldTypes[3] = "bytes";
        
        // v: starts after baseETHMessage = 84 + 140 = 224, length = 1
        fieldOffsets[4] = 224;
        fieldLengths[4] = 1;
        fieldTypes[4] = "uint8";
        
        // r: starts after v = 224 + 1 = 225, length = 32
        fieldOffsets[5] = 225;
        fieldLengths[5] = 32;
        fieldTypes[5] = "bytes32";
        
        // s: starts after r = 225 + 32 = 257, length = 32
        fieldOffsets[6] = 257;
        fieldLengths[6] = 32;
        fieldTypes[6] = "bytes32";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 40, fieldOffsets, fieldLengths, fieldTypes, true);
        
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
        
        // oldEthAddress: starts after pattern (65) = 65
        fieldOffsets[0] = 65;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // " to " pattern: starts after oldEthAddress = 65 + 20 = 85, length = 4
        fieldOffsets[1] = 85;
        fieldLengths[1] = 4;
        fieldTypes[1] = "string";
        
        // newEthAddress: starts after " to " = 85 + 4 = 89, length = 20
        fieldOffsets[2] = 89;
        fieldLengths[2] = 20;
        fieldTypes[2] = "address";
        
        // pqNonce: starts after newEthAddress = 89 + 20 = 109, length = 32
        fieldOffsets[3] = 109;
        fieldLengths[3] = 32;
        fieldTypes[3] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 65, fieldOffsets, fieldLengths, fieldTypes, true);
        
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
        
        // pqFingerprint: starts after pattern (47) = 47
        fieldOffsets[0] = 47;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 47 + 20 = 67
        fieldOffsets[1] = 67;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        
        // pqFingerprint: starts after pattern (49) = 49
        fieldOffsets[0] = 49;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 49 + 20 = 69, length = 111
        fieldOffsets[1] = 69;
        fieldLengths[1] = 111;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 69 + 111 = 180, length = 40
        fieldOffsets[2] = 180;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 180 + 40 = 220, length = 32 * 32 = 1024
        fieldOffsets[3] = 220;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 220 + 1024 = 1244, length = 32 * 32 = 1024
        fieldOffsets[4] = 1244;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1244 + 1024 = 2268, length = 32
        fieldOffsets[5] = 2268;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2268 + 32 = 2300, length = 32
        fieldOffsets[6] = 2300;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 49, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        
        // pqFingerprint: starts after pattern (52) = 52
        fieldOffsets[0] = 52;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 52 + 20 = 72, length = 173
        fieldOffsets[1] = 72;
        fieldLengths[1] = 173;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 72 + 173 = 245, length = 40
        fieldOffsets[2] = 245;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 245 + 40 = 285, length = 32 * 32 = 1024
        fieldOffsets[3] = 285;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 285 + 1024 = 1309, length = 32 * 32 = 1024
        fieldOffsets[4] = 1309;
        fieldLengths[4] = 1024;
        fieldTypes[4] = "uint256[32]";
        
        // hint: starts after cs2 = 1309 + 1024 = 2333, length = 32
        fieldOffsets[5] = 2333;
        fieldLengths[5] = 32;
        fieldTypes[5] = "uint256";
        
        // ethNonce: starts after hint = 2333 + 32 = 2365, length = 32
        fieldOffsets[6] = 2365;
        fieldLengths[6] = 32;
        fieldTypes[6] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 52, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        uint startOffset = 0; // No DOMAIN_SEPARATOR to skip
        uint patternIndex = findPattern(message, pattern, false); // false = don't skip DOMAIN_SEPARATOR
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
     * @param skipDomainSeparator Whether to skip the 32-byte domain separator (true for PQ messages, false for ETH messages)
     * @return parsedFields Array of parsed field values as bytes
     */
    function parseMessageFields(
        bytes memory message,
        bytes memory expectedPattern,
        uint256 patternLength,
        uint256[] memory fieldOffsets,
        uint256[] memory fieldLengths,
        string[] memory fieldTypes,
        bool skipDomainSeparator
    ) internal pure returns (bytes[] memory parsedFields) {
        require(fieldOffsets.length == fieldLengths.length, "Field offsets and lengths must match");
        require(fieldOffsets.length == fieldTypes.length, "Field offsets and types must match");
        
        uint256 patternIndex = findPattern(message, expectedPattern, skipDomainSeparator);
        
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
            uint256 actualFieldStart;
            if (skipDomainSeparator) {
                // For PQ messages: patternIndex + fieldOffsets[i] (fieldOffsets are relative to pattern start)
                actualFieldStart = patternIndex + fieldOffsets[i];
            } else {
                // For ETH messages: patternIndex + patternLength + (fieldOffsets[i] - patternLength)
                actualFieldStart = patternIndex + patternLength + (fieldOffsets[i] - patternLength);
            }
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
        
        // pqFingerprint: starts after pattern (53) = 53
        fieldOffsets[0] = 53;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 53 + 20 = 73
        fieldOffsets[1] = 73;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 53, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        
        // pqFingerprint: starts after pattern (47) = 47
        fieldOffsets[0] = 47;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // ethNonce: starts after pqFingerprint = 47 + 20 = 67
        fieldOffsets[1] = 67;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 47, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        // ethAddress: starts after pattern (44) = 44
        fieldOffsets[0] = 44;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        // pqNonce: starts after ethAddress = 44 + 20 = 64
        fieldOffsets[1] = 64;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 44, fieldOffsets, fieldLengths, fieldTypes, true);
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
        
        // ethAddress: starts after pattern (38) = 38
        fieldOffsets[0] = 38;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 38 + 20 = 58
        fieldOffsets[1] = 58;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 38, fieldOffsets, fieldLengths, fieldTypes, true);
        
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
        
        // ethAddress: starts after pattern (46) = 46
        fieldOffsets[0] = 46;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // pqNonce: starts after ethAddress = 46 + 20 = 66
        fieldOffsets[1] = 66;
        fieldLengths[1] = 32;
        fieldTypes[1] = "uint256";
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 46, fieldOffsets, fieldLengths, fieldTypes, true);
        
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
        
        // pqFingerprint: starts after pattern (52) = 52
        fieldOffsets[0] = 52;
        fieldLengths[0] = 20;
        fieldTypes[0] = "address";
        
        // basePQMessage: starts after pqFingerprint = 52 + 20 = 72, length = 173
        fieldOffsets[1] = 72;
        fieldLengths[1] = 173;
        fieldTypes[1] = "bytes";
        
        // salt: starts after basePQMessage = 72 + 173 = 245, length = 40
        fieldOffsets[2] = 245;
        fieldLengths[2] = 40;
        fieldTypes[2] = "bytes";
        
        // cs1: starts after salt = 245 + 40 = 285, length = 32 * 32 = 1024
        fieldOffsets[3] = 285;
        fieldLengths[3] = 1024;
        fieldTypes[3] = "uint256[32]";
        
        // cs2: starts after cs1 = 285 + 1024 = 1309, length = 32 * 32 = 1024
        fieldOffsets[4] = 1309;
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
        
        bytes[] memory parsedFields = parseMessageFields(message, pattern, 52, fieldOffsets, fieldLengths, fieldTypes, false);
        
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
        return findPattern(message, pattern, false) != type(uint).max;
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
        return findPattern(message, pattern, false) != type(uint).max;
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
        return findPattern(message, pattern, false) != type(uint).max;
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
        return findPattern(message, pattern, false) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains intent text for change ETH Address
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
     * Expected format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
     */
    function validateETHChangeETHAddressIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to change ETH Address and bond with Epervier Fingerprint ";
        return findPattern(message, pattern, false) != type(uint).max;
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
        return findPattern(message, pattern, false) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains removal text for change ETH Address intent
     * Expected format: DOMAIN_SEPARATOR + "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function validateETHRemoveChangeIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Remove change intent from Epervier Fingerprint ";
        return findPattern(message, pattern, false) != type(uint).max;
    }

    /**
     * @dev Validate that ETH message contains intent text for unregistration
     * Expected format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint " + pqFingerprint + ethNonce
     */
    function validateETHUnregistrationIntentMessage(bytes memory message) internal pure returns (bool) {
        bytes memory pattern = "Intent to unregister from Epervier Fingerprint ";
        return findPattern(message, pattern, false) != type(uint).max;
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
