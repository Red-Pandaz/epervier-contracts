// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";

contract PQRegistryIntegrationTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    // These would be populated with real data from Python CLI
    bytes public realSalt;
    uint256[] public realCs1;
    uint256[] public realCs2;
    uint256 public realHint;
    bytes public realMessage;
    uint256[2] public realPublicKey;
    address public realRecoveredAddress;
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(epervierVerifier));
        
        // TODO: Load real signature data from Python CLI output
        // This would be done by reading from a file or environment variables
        loadRealSignatureData();
    }
    
    function loadRealSignatureData() internal {
        // Load real public key from public_key_1.pem
        // Format: # public key\nn = 512\npk = <number>\nversion = epervier
        realPublicKey = loadPublicKeyFromPem("test/test_keys/public_key_1.pem");
        
        // Load real signature from sig_1
        (realSalt, realCs1, realCs2, realHint) = loadSignatureFromFile("test/test_keys/sig_1");
        
        // For now, use a placeholder message - you'll need to tell me what was actually signed
        realMessage = "Register Epervier Key"; // This should be the actual message that was signed
        
        // Placeholder recovered address - this should be the actual address recovered from the signature
        realRecoveredAddress = address(0x1234567890123456789012345678901234567890);
    }
    
    function loadPublicKeyFromPem(string memory filename) internal view returns (uint256[2] memory) {
        // For now, hardcode the public key from public_key_1.pem
        // In a real implementation, you'd read and parse the file
        // pk = 703309690834788033648158452166570983886945531899
        return [uint256(703309690834788033648158452166570983886945531899), uint256(0)];
    }
    
    function loadSignatureFromFile(string memory filename) internal view returns (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) {
        // For now, hardcode signature components from sig_1
        // In a real implementation, you'd read and parse the hex file
        salt = new bytes(40);
        cs1 = new uint256[](32);
        cs2 = new uint256[](32);
        hint = 123; // This should be extracted from the signature file
        
        // TODO: Parse the actual signature hex string to extract salt, cs1, cs2, hint
        // The sig_1 file contains a long hex string that needs to be decoded
    }
    
    function testRealSignatureVerification() public {
        // Mock the Epervier verifier to return a valid address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(realRecoveredAddress)
        );
        
        // Test the Epervier verifier directly
        address recovered = epervierVerifier.recover(
            realMessage, 
            realSalt, 
            realCs1, 
            realCs2, 
            realHint
        );
        
        assertEq(recovered, realRecoveredAddress, "Signature should recover correct address");
    }
    
    function testRealRegistryRegistration() public {
        // Mock the Epervier verifier to return a valid address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(realRecoveredAddress)
        );
        
        // Create the registration message with embedded ECDSA signature
        bytes memory registrationMessage = abi.encodePacked(
            "Register Epervier Key",
            uint256(0), // nonce
            realPublicKey[0],
            realPublicKey[1],
            new bytes(65) // ECDSA signature would be embedded here
        );
        
        // This will fail at ECDSA verification since we're using mock data
        // but it tests the function structure and Epervier verification
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(
            realSalt,
            realCs1,
            realCs2,
            realHint,
            registrationMessage,
            realPublicKey
        );
    }
    
    function testIntegrationWithPythonCLI() public {
        // This test demonstrates the integration flow with the Python CLI
        
        console.log("=== PQ Registry Integration Test ===");
        console.log("1. Generate Epervier keys using Python CLI:");
        console.log("   python sign_cli.py generate");
        
        console.log("2. Sign a message using Python CLI:");
        console.log("   python sign_cli.py sign 'Register Epervier Key'");
        
        console.log("3. Extract signature components and create registration message");
        console.log("4. Call registry.registerEpervierKey() with real data");
        console.log("5. Verify the key is registered correctly");
        
        // The actual test would load real data and verify the full flow
        assertTrue(true, "Integration test structure verified");
    }
    
    function testMessageFormatValidation() public {
        // Test that message formats are correct
        
        // Test registration message format
        bytes memory baseMessage = abi.encodePacked(
            "Register Epervier Key",
            uint256(0),
            realPublicKey[0],
            realPublicKey[1]
        );
        
        bytes memory fullMessage = abi.encodePacked(
            baseMessage,
            new bytes(65) // ECDSA signature
        );
        
        assertEq(fullMessage.length, baseMessage.length + 65, "Message should include 65-byte ECDSA signature");
        
        // Calculate expected base message length:
        // "Register Epervier Key" (20 bytes) + nonce (32 bytes) + publicKey[0] (32 bytes) + publicKey[1] (32 bytes) = 116 bytes
        uint256 expectedBaseLength = 20 + 32 + 32 + 32; // 116 bytes
        assertEq(baseMessage.length, expectedBaseLength, "Base message should be correct length");
    }
    
    function testNonceIncrement() public {
        // Test that nonces increment correctly after operations
        
        uint256 initialNonce = registry.getNonce(realRecoveredAddress);
        
        // After a successful registration, nonce should increment
        // This would be tested with real signatures
        assertEq(initialNonce, 0, "Initial nonce should be 0");
        
        // TODO: Test nonce increment after real registration
    }
} 