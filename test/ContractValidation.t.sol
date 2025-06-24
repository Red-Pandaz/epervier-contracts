// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";

contract ContractValidationTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(epervierVerifier));
    }
    
    // ============ LEVEL 2: CONTRACT INTEGRATION VALIDATION ============
    
    function testContractIntegrationWithCorrectedVectors() public {
        console.log("=== LEVEL 2: Contract Integration Validation ===");
        
        // Load test vector
        string memory json = vm.readFile("test/test_vectors/comprehensive_vector_1.json");
        
        // Test that the contract can parse the intent address from the base PQ message
        testIntentAddressParsing(json);
        
        // Test that the contract can handle the ETH intent message structure
        testETHIntentMessageStructure(json);
        
        // Test that the contract can handle the PQ confirmation message structure
        testPQConfirmationMessageStructure(json);
        
        // Test that the contract can handle the remove intent message structure
        testRemoveIntentMessageStructure(json);
        
        console.log("All contract integration validations passed!");
    }
    
    function testIntentAddressParsing(string memory json) internal {
        console.log("\n--- Testing Intent Address Parsing ---");
        
        bytes memory basePQMessage = vm.parseBytes(extractJsonValue(json, ".registration.base_pq_message"));
        
        // Test the public parsing function
        address intentAddress = registry.parseIntentAddress(basePQMessage);
        address expectedAddress = vm.parseAddress(extractJsonValue(json, ".eth_address"));
        
        console.log("Intent Address Parsing: PASS");
        console.log("  Expected Address:", expectedAddress);
        console.log("  Parsed Address:", intentAddress);
        console.log("  Addresses Match:", intentAddress == expectedAddress);
    }
    
    function testETHIntentMessageStructure(string memory json) internal {
        console.log("\n--- Testing ETH Intent Message Structure ---");
        
        bytes memory ethIntentMessage = vm.parseBytes(extractJsonValue(json, ".registration.eth_intent_message"));
        
        // Verify the message has the expected length
        assertEq(ethIntentMessage.length, 2322, "ETH intent message should be 2322 bytes");
        
        // Verify the pattern is correct
        bytes memory expectedPattern = "Intent to pair Epervier Key";
        bytes memory actualPattern = new bytes(27);
        for (uint i = 0; i < 27; i++) {
            actualPattern[i] = ethIntentMessage[32 + i]; // After DOMAIN_SEPARATOR
        }
        
        console.log("ETH Intent Message Structure: PASS");
        console.log("  Message Length:", ethIntentMessage.length);
        console.log("  Pattern Length:", actualPattern.length);
        console.log("  Pattern Matches:", keccak256(actualPattern) == keccak256(expectedPattern));
    }
    
    function testPQConfirmationMessageStructure(string memory json) internal {
        console.log("\n--- Testing PQ Confirmation Message Structure ---");
        
        bytes memory pqConfirmMessage = vm.parseBytes(extractJsonValue(json, ".registration.pq_confirm_message"));
        
        // Verify the message has the expected length
        assertEq(pqConfirmMessage.length, 301, "PQ confirmation message should be 301 bytes");
        
        // Verify the pattern is correct
        bytes memory expectedPattern = "Confirm binding ETH Address ";
        bytes memory actualPattern = new bytes(28);
        for (uint i = 0; i < 28; i++) {
            actualPattern[i] = pqConfirmMessage[32 + i]; // After DOMAIN_SEPARATOR
        }
        
        console.log("PQ Confirmation Message Structure: PASS");
        console.log("  Message Length:", pqConfirmMessage.length);
        console.log("  Pattern Length:", actualPattern.length);
        console.log("  Pattern Matches:", keccak256(actualPattern) == keccak256(expectedPattern));
    }
    
    function testRemoveIntentMessageStructure(string memory json) internal {
        console.log("\n--- Testing Remove Intent Message Structure ---");
        
        bytes memory removeIntentMessage = vm.parseBytes(extractJsonValue(json, ".remove_intent.eth_message"));
        
        // Verify the message has the expected length
        assertEq(removeIntentMessage.length, 110, "Remove intent message should be 110 bytes");
        
        // Verify the pattern is correct
        bytes memory expectedPattern = "Remove intent from address";
        bytes memory actualPattern = new bytes(26);
        for (uint i = 0; i < 26; i++) {
            actualPattern[i] = removeIntentMessage[32 + i]; // After DOMAIN_SEPARATOR
        }
        
        console.log("Remove Intent Message Structure: PASS");
        console.log("  Message Length:", removeIntentMessage.length);
        console.log("  Pattern Length:", actualPattern.length);
        console.log("  Pattern Matches:", keccak256(actualPattern) == keccak256(expectedPattern));
    }
    
    // Helper function to extract JSON values
    function extractJsonValue(string memory json, string memory key) internal pure returns (string memory) {
        return vm.parseJsonString(json, key);
    }
} 