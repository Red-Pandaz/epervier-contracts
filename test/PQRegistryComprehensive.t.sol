// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {PQRegistry} from "../src/PQRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PQRegistryComprehensiveTest is Test {
    using ECDSA for bytes32;

    PQRegistry public registry;
    
    // Test data structure
    struct TestVector {
        string ethAddress;
        string nextEthAddress;
        uint256[2] pqPublicKey;
        string pqPublicKeyHash;
        
        // Registration data
        string basePqMessage;
        string fullPqMessage;
        string ethIntentMessage;
        string ethConfirmMessage;
        string ethIntentSignature;
        string ethConfirmSignature;
        string epervierSalt;
        uint256[] epervierCs1;
        uint256[] epervierCs2;
        uint256[] epervierHint;
        
        // Change ETH address data
        string changeBasePqMessage;
        string changeEthConfirmMessage;
        string changeEthConfirmSignature;
        string changeEpervierSalt;
        uint256[] changeEpervierCs1;
        uint256[] changeEpervierCs2;
        uint256[] changeEpervierHint;
        
        // Unregistration data
        string unregBasePqMessage;
        string unregEpervierSalt;
        uint256[] unregEpervierCs1;
        uint256[] unregEpervierCs2;
        uint256[] unregEpervierHint;
    }
    
    TestVector[] public testVectors;
    
    function setUp() public {
        // Deploy a mock Epervier verifier for testing
        address mockEpervierVerifier = address(0x1234567890123456789012345678901234567890);
        registry = new PQRegistry(mockEpervierVerifier);
        loadTestVectors();
    }
    
    function loadTestVectors() internal {
        // Load all comprehensive test vectors
        for (uint i = 1; i <= 5; i++) {
            string memory filename = string.concat("test_vectors/comprehensive_vector_", vm.toString(i), ".json");
            string memory json = vm.readFile(filename);
            
            TestVector memory vector;
            
            // Parse JSON data
            vector.ethAddress = vm.parseJsonString(json, "$.eth_address");
            vector.nextEthAddress = vm.parseJsonString(json, "$.next_eth_address");
            vector.pqPublicKeyHash = vm.parseJsonString(json, "$.pq_public_key_hash");
            
            // Parse PQ public key
            vector.pqPublicKey[0] = vm.parseJsonUint(json, "$.pq_public_key[0]");
            vector.pqPublicKey[1] = vm.parseJsonUint(json, "$.pq_public_key[1]");
            
            // Registration data
            vector.basePqMessage = vm.parseJsonString(json, "$.registration.base_pq_message");
            vector.fullPqMessage = vm.parseJsonString(json, "$.registration.full_pq_message");
            vector.ethIntentMessage = vm.parseJsonString(json, "$.registration.eth_intent_message");
            vector.ethConfirmMessage = vm.parseJsonString(json, "$.registration.eth_confirm_message");
            vector.ethIntentSignature = vm.parseJsonString(json, "$.registration.eth_intent_signature");
            vector.ethConfirmSignature = vm.parseJsonString(json, "$.registration.eth_confirm_signature");
            vector.epervierSalt = vm.parseJsonString(json, "$.registration.epervier_salt");
            
            // Parse arrays
            vector.epervierCs1 = vm.parseJsonUintArray(json, "$.registration.epervier_cs1");
            vector.epervierCs2 = vm.parseJsonUintArray(json, "$.registration.epervier_cs2");
            vector.epervierHint = vm.parseJsonUintArray(json, "$.registration.epervier_hint");
            
            // Change ETH address data
            vector.changeBasePqMessage = vm.parseJsonString(json, "$.change_eth_address.base_pq_message");
            vector.changeEthConfirmMessage = vm.parseJsonString(json, "$.change_eth_address.eth_confirm_message");
            vector.changeEthConfirmSignature = vm.parseJsonString(json, "$.change_eth_address.eth_confirm_signature");
            vector.changeEpervierSalt = vm.parseJsonString(json, "$.change_eth_address.epervier_salt");
            vector.changeEpervierCs1 = vm.parseJsonUintArray(json, "$.change_eth_address.epervier_cs1");
            vector.changeEpervierCs2 = vm.parseJsonUintArray(json, "$.change_eth_address.epervier_cs2");
            vector.changeEpervierHint = vm.parseJsonUintArray(json, "$.change_eth_address.epervier_hint");
            
            // Unregistration data
            vector.unregBasePqMessage = vm.parseJsonString(json, "$.unregistration.base_pq_message");
            vector.unregEpervierSalt = vm.parseJsonString(json, "$.unregistration.epervier_salt");
            vector.unregEpervierCs1 = vm.parseJsonUintArray(json, "$.unregistration.epervier_cs1");
            vector.unregEpervierCs2 = vm.parseJsonUintArray(json, "$.unregistration.epervier_cs2");
            vector.unregEpervierHint = vm.parseJsonUintArray(json, "$.unregistration.epervier_hint");
            
            testVectors.push(vector);
        }
    }
    
    // Helper function to extract ETH signature from full PQ message
    function extractEthSignature(string memory fullPqMessage) internal view returns (bytes memory) {
        bytes memory fullMessage = vm.parseBytes(fullPqMessage);
        
        // Extract last 65 bytes (ETH signature)
        require(fullMessage.length >= 65, "Message too short for ETH signature");
        bytes memory ethSig = new bytes(65);
        for (uint i = 0; i < 65; i++) {
            ethSig[i] = fullMessage[fullMessage.length - 65 + i];
        }
        return ethSig;
    }
    
    // Test 1: Complete registration flow (intent + confirm)
    function testCompleteRegistration() public {
        for (uint i = 0; i < testVectors.length; i++) {
            TestVector memory vector = testVectors[i];
            
            // Step 1: Submit registration intent
            bytes memory ethSig = extractEthSignature(vector.fullPqMessage);
            
            registry.submitRegistrationIntent(
                vm.parseBytes(vector.fullPqMessage),
                hex"", // PQ signature is embedded in the message
                vm.parseBytes(vector.epervierSalt),
                vector.epervierCs1,
                vector.epervierCs2,
                vector.epervierHint[0], // hint is a single uint256
                vector.pqPublicKey,
                0, // ethNonce
                ethSig
            );
            
            // Verify intent was created by checking the pendingIntents mapping
            bytes32 pqFingerprint = keccak256(abi.encodePacked(vector.pqPublicKey[0], vector.pqPublicKey[1]));
            address intentAddress = vm.parseAddress(vector.ethAddress);
            
            // Access the struct fields individually
            bytes32 storedFingerprint = registry.pendingIntents(intentAddress, 0); // pqFingerprint
            uint256 storedNonce = registry.pendingIntents(intentAddress, 4); // ethNonce
            assertEq(storedFingerprint, pqFingerprint);
            assertEq(storedNonce, 0);
            
            // Step 2: Confirm registration
            registry.confirmRegistration(
                vm.parseBytes(vector.basePqMessage),
                hex"", // PQ signature is embedded in the message
                vm.parseBytes(vector.epervierSalt),
                vector.epervierCs1,
                vector.epervierCs2,
                vector.epervierHint[0], // hint is a single uint256
                vector.pqPublicKey,
                0, // ethNonce
                vm.parseBytes(vector.ethConfirmSignature)
            );
            
            // Verify registration was confirmed
            address registeredEth = registry.epervierKeyToAddress(pqFingerprint);
            assertEq(registeredEth, intentAddress);
        }
    }
    
    // Test 2: Change ETH address flow
    function testChangeEthAddress() public {
        for (uint i = 0; i < testVectors.length; i++) {
            TestVector memory vector = testVectors[i];
            
            // First register the account
            bytes memory ethSig = extractEthSignature(vector.fullPqMessage);
            
            registry.submitRegistrationIntent(
                vm.parseBytes(vector.fullPqMessage),
                hex"",
                vm.parseBytes(vector.epervierSalt),
                vector.epervierCs1,
                vector.epervierCs2,
                vector.epervierHint[0],
                vector.pqPublicKey,
                0,
                ethSig
            );
            
            registry.confirmRegistration(
                vm.parseBytes(vector.basePqMessage),
                hex"",
                vm.parseBytes(vector.epervierSalt),
                vector.epervierCs1,
                vector.epervierCs2,
                vector.epervierHint[0],
                vector.pqPublicKey,
                0,
                vm.parseBytes(vector.ethConfirmSignature)
            );
            
            // Now change ETH address
            registry.submitChangeETHAddressIntent(
                vm.parseBytes(vector.changeBasePqMessage),
                hex"",
                vm.parseBytes(vector.changeEpervierSalt),
                vector.changeEpervierCs1,
                vector.changeEpervierCs2,
                vector.changeEpervierHint[0],
                vector.pqPublicKey,
                0, // pqNonce
                vm.parseBytes(vector.changeEthConfirmSignature)
            );
            
            // Verify ETH address was changed
            address newEth = registry.epervierKeyToAddress(keccak256(abi.encodePacked(vector.pqPublicKey[0], vector.pqPublicKey[1])));
            assertEq(newEth, vm.parseAddress(vector.nextEthAddress));
        }
    }
    
    // Test 3: Unregistration flow
    function testUnregistration() public {
        for (uint i = 0; i < testVectors.length; i++) {
            TestVector memory vector = testVectors[i];
            
            // First register the account
            bytes memory ethSig = extractEthSignature(vector.fullPqMessage);
            
            registry.submitRegistrationIntent(
                vm.parseBytes(vector.fullPqMessage),
                hex"",
                vm.parseBytes(vector.epervierSalt),
                vector.epervierCs1,
                vector.epervierCs2,
                vector.epervierHint[0],
                vector.pqPublicKey,
                0,
                ethSig
            );
            
            registry.confirmRegistration(
                vm.parseBytes(vector.basePqMessage),
                hex"",
                vm.parseBytes(vector.epervierSalt),
                vector.epervierCs1,
                vector.epervierCs2,
                vector.epervierHint[0],
                vector.pqPublicKey,
                0,
                vm.parseBytes(vector.ethConfirmSignature)
            );
            
            // Now unregister
            registry.submitUnregistrationIntent(
                vm.parseBytes(vector.unregBasePqMessage),
                hex"",
                vm.parseBytes(vector.unregEpervierSalt),
                vector.unregEpervierCs1,
                vector.unregEpervierCs2,
                vector.unregEpervierHint[0],
                vector.pqPublicKey,
                0, // ethNonce
                hex"" // ETH signature for unregistration
            );
            
            // Verify account was unregistered
            address ethAddr = registry.epervierKeyToAddress(keccak256(abi.encodePacked(vector.pqPublicKey[0], vector.pqPublicKey[1])));
            assertEq(ethAddr, address(0));
        }
    }
    
    // Test 4: Replay attack prevention
    function testReplayAttackPrevention() public {
        TestVector memory vector = testVectors[0];
        bytes memory ethSig = extractEthSignature(vector.fullPqMessage);
        
        // Create intent once
        registry.submitRegistrationIntent(
            vm.parseBytes(vector.fullPqMessage),
            hex"",
            vm.parseBytes(vector.epervierSalt),
            vector.epervierCs1,
            vector.epervierCs2,
            vector.epervierHint[0],
            vector.pqPublicKey,
            0,
            ethSig
        );
        
        // Try to create intent again with same nonce - should fail
        vm.expectRevert();
        registry.submitRegistrationIntent(
            vm.parseBytes(vector.fullPqMessage),
            hex"",
            vm.parseBytes(vector.epervierSalt),
            vector.epervierCs1,
            vector.epervierCs2,
            vector.epervierHint[0],
            vector.pqPublicKey,
            0,
            ethSig
        );
    }
    
    // Test 5: Invalid nonce handling
    function testInvalidNonce() public {
        TestVector memory vector = testVectors[0];
        
        // Try to create intent with non-zero nonce when no intent exists
        vm.expectRevert();
        registry.submitRegistrationIntent(
            vm.parseBytes(vector.fullPqMessage),
            hex"",
            vm.parseBytes(vector.changeEpervierSalt), // This has different nonce
            vector.changeEpervierCs1,
            vector.changeEpervierCs2,
            vector.changeEpervierHint[0],
            vector.pqPublicKey,
            1, // Wrong nonce
            hex""
        );
    }
    
    // Test 6: Multiple operations with proper nonce progression
    function testNonceProgression() public {
        TestVector memory vector = testVectors[0];
        bytes memory ethSig = extractEthSignature(vector.fullPqMessage);
        
        // Registration with nonce 0
        registry.submitRegistrationIntent(
            vm.parseBytes(vector.fullPqMessage),
            hex"",
            vm.parseBytes(vector.epervierSalt),
            vector.epervierCs1,
            vector.epervierCs2,
            vector.epervierHint[0],
            vector.pqPublicKey,
            0,
            ethSig
        );
        
        registry.confirmRegistration(
            vm.parseBytes(vector.basePqMessage),
            hex"",
            vm.parseBytes(vector.epervierSalt),
            vector.epervierCs1,
            vector.epervierCs2,
            vector.epervierHint[0],
            vector.pqPublicKey,
            0,
            vm.parseBytes(vector.ethConfirmSignature)
        );
        
        // Change ETH address with nonce 0 (for new address)
        registry.submitChangeETHAddressIntent(
            vm.parseBytes(vector.changeBasePqMessage),
            hex"",
            vm.parseBytes(vector.changeEpervierSalt),
            vector.changeEpervierCs1,
            vector.changeEpervierCs2,
            vector.changeEpervierHint[0],
            vector.pqPublicKey,
            0,
            vm.parseBytes(vector.changeEthConfirmSignature)
        );
        
        // Unregistration with nonce 1
        registry.submitUnregistrationIntent(
            vm.parseBytes(vector.unregBasePqMessage),
            hex"",
            vm.parseBytes(vector.unregEpervierSalt),
            vector.unregEpervierCs1,
            vector.unregEpervierCs2,
            vector.unregEpervierHint[0],
            vector.pqPublicKey,
            1, // ethNonce incremented
            hex""
        );
        
        // Verify final state
        address ethAddr = registry.epervierKeyToAddress(keccak256(abi.encodePacked(vector.pqPublicKey[0], vector.pqPublicKey[1])));
        assertEq(ethAddr, address(0));
    }
} 