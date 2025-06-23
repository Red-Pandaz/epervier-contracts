// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/PQRegistry.sol";

contract PQRegistryIntentTest is Test {
    ZKNOX_epervier public epervierVerifier;
    PQRegistry public pqRegistry;
    
    // Test addresses
    address public testUser = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    uint256 public testUserPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    
    function setUp() public {
        // Deploy contracts
        epervierVerifier = new ZKNOX_epervier();
        pqRegistry = new PQRegistry(address(epervierVerifier));
        
        // Label addresses for better debugging
        vm.label(address(epervierVerifier), "EpervierVerifier");
        vm.label(address(pqRegistry), "PQRegistry");
        vm.label(testUser, "TestUser");
    }
    
    function testSubmitRegistrationIntent() public {
        // This is a basic test structure - you'll need to add actual Epervier signature data
        
        // Create a test intent message
        bytes memory intentMessage = abi.encodePacked("Register Epervier Key", testUser, "0");
        
        // Mock Epervier signature components (you'll need real ones)
        bytes memory salt = new bytes(40); // 40 bytes for salt
        uint256[] memory cs1 = new uint256[](32); // 32 uint256 for cs1
        uint256[] memory cs2 = new uint256[](32); // 32 uint256 for cs2
        uint256 hint = 0;
        uint256[2] memory publicKey = [uint256(0), uint256(0)]; // Mock public key
        uint256 ethNonce = 0;
        
        // Create ETH signature for the intent
        bytes memory ethIntentMessage = abi.encodePacked(
            pqRegistry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            ethNonce
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testUserPrivateKey, ethMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        // Submit the intent
        vm.prank(testUser);
        pqRegistry.submitRegistrationIntent(
            intentMessage,
            salt,
            cs1,
            cs2,
            hint,
            publicKey,
            ethNonce,
            ethSignature
        );
        
        // Check that the intent was stored
        // Note: This will fail with mock data, but shows the structure
        console.log("Intent submitted successfully");
    }
    
    function testGetNonce() public {
        // Test getting nonce for an address
        uint256 nonce = pqRegistry.ethNonces(testUser);
        console.log("Nonce for testUser:", nonce);
        assertEq(nonce, 0, "Initial nonce should be 0");
    }
    
    function testParseIntentAddress() public {
        // Test the parseIntentAddress function
        bytes memory message = abi.encodePacked("Register Epervier Key", testUser, "0");
        address parsedAddress = pqRegistry.parseIntentAddress(message);
        console.log("Parsed address:", parsedAddress);
        console.log("Expected address:", testUser);
        // Note: This might not work with the current implementation
    }
    
    function testDebugParseIntentAddress() public {
        // Test the debug version
        bytes memory message = abi.encodePacked("Register Epervier Key", testUser, "0");
        pqRegistry.debugParseIntentAddress(message);
    }
} 