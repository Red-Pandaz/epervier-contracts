// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/libraries/MessageParser.sol";

contract DebugPatternTest is Test {

    function testDebugPattern() public {
        // Load the test vector
        string memory vectorsJson = vm.readFile("test/test_vectors/advanced/test4_pq_cancels_change_eth_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(vectorsJson, ".change_eth_address_intent[1].pq_message"));
       
        // Check the first 100 bytes as hex
        console.log("Message length:", pqMessage.length);
        console.log("First 32 bytes (DOMAIN_SEPARATOR):");
        for (uint i = 0; i < 32; i++) {
            console.log("Byte", i, uint8(pqMessage[i]));
        }
        
        console.log("Next 40 bytes (pattern):");
        for (uint i = 32; i < 72; i++) {
            console.log("Byte", i, uint8(pqMessage[i]));
        }
        
        // Check if the pattern is at the expected position
        bytes memory pattern = "Intent to change bound ETH Address from ";
        console.log("Pattern length:", pattern.length);
        
        // Check if the pattern matches at position 32
        bool patternMatches = true;
        for (uint i = 0; i < pattern.length; i++) {
            if (pqMessage[32 + i] != pattern[i]) {
                patternMatches = false;
                console.log("Pattern mismatch at position", i, uint8(pattern[i]), uint8(pqMessage[32 + i]));
                break;
            }
        }
        console.log("Pattern matches at position 32:", patternMatches);
        
        // Try to find the pattern using findPattern
        uint patternIndex = MessageParser.findPattern(pqMessage, pattern, true);
        console.log("Pattern found at index:", patternIndex);
        
        // Try to parse the message
        (
            address oldEthAddress,
            address newEthAddress,
            uint256 pqNonce,
            bytes memory baseETHMessage,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = MessageParser.parsePQChangeETHAddressIntentMessage(pqMessage, 0x07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92);
        
        console.log("Parse successful");
        console.log("Old ETH Address:", oldEthAddress);
        console.log("New ETH Address:", newEthAddress);
    }
} 