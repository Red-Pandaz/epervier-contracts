// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../PQRegistry_main_functions.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract PQRegistryComprehensiveTest is Test {
    using ECDSA for bytes32;
    using Strings for string;
    
    PQRegistryMainFunctions public registry;
    ZKNOX_epervier public epervierVerifier;
    
    // Test addresses
    address public testETHAddress = address(0x1234567890123456789012345678901234567890);
    address public pqFingerprint = address(0x1111111111111111111111111111111111111111);
    
    // Test data
    uint256 public testETHNonce = 0;
    uint256 public testPQNonce = 0;
    
    // Actor data structure
    struct Actor {
        address ethAddress;
        address pqFingerprint;
        uint256 ethPrivateKey;
        string pqPrivateKeyFile;
        string pqPublicKeyFile;
    }
    
    // Actor mapping
    mapping(string => Actor) public actors;
    
    // Actor names array for easy iteration
    string[] public actorNames;
    
    // Test events for verification
    event RegistrationConfirmed(address indexed ethAddress, address indexed pqFingerprint);
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistryMainFunctions();
        
        // Set a timestamp for the test environment
        vm.warp(1640995200); // January 1, 2022 00:00:00 UTC
        
        // Load actor data from centralized config
        loadActorsConfig();
    }
    
    function loadActorsConfig() internal {
        // Load the centralized actors config
        string memory jsonData = vm.readFile("test/test_keys/actors_config.json");
        
        // Define actor names
        actorNames = new string[](10);
        actorNames[0] = "alice";
        actorNames[1] = "bob";
        actorNames[2] = "charlie";
        actorNames[3] = "danielle";
        actorNames[4] = "eve";
        actorNames[5] = "frank";
        actorNames[6] = "grace";
        actorNames[7] = "henry";
        actorNames[8] = "iris";
        actorNames[9] = "jack";
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            string memory actorPath = string.concat(".actors.", actorName);
            
            actors[actorName] = Actor({
                ethAddress: vm.parseAddress(vm.parseJsonString(jsonData, string.concat(actorPath, ".eth_address"))),
                pqFingerprint: vm.parseAddress(vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_fingerprint"))),
                ethPrivateKey: vm.parseUint(vm.parseJsonString(jsonData, string.concat(actorPath, ".eth_private_key"))),
                pqPrivateKeyFile: vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_private_key_file")),
                pqPublicKeyFile: vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_public_key_file"))
            });
        }
    }
    
    function getActor(string memory actorName) internal view returns (Actor memory) {
        return actors[actorName];
    }
    
    // Helper function to parse signature
    function parseSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "Invalid signature length");
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid signature 'v' value");
    }
    
    // Helper function to tamper with a message (flip a bit in an address)
    function tamperWithAddress(bytes memory message, uint256 addressOffset, uint256 bitToFlip) internal pure returns (bytes memory) {
        bytes memory tampered = new bytes(message.length);
        for (uint i = 0; i < message.length; i++) {
            tampered[i] = message[i];
        }
        
        // Flip a bit in the address field
        uint256 byteIndex = addressOffset + (bitToFlip / 8);
        uint256 bitInByte = bitToFlip % 8;
        tampered[byteIndex] = bytes1(uint8(tampered[byteIndex]) ^ uint8(1 << bitInByte));
        
        return tampered;
    }
    
    // Helper function to create invalid signature components
    function createInvalidSignature() internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        return (27, bytes32(0), bytes32(0));
    }
    
    // Helper function to get the domain separator
    function getDomainSeparator() internal pure returns (bytes32) {
        return keccak256("PQRegistry");
    }
    
    // Helper function to create a tampered message with wrong domain separator
    function tamperWithDomainSeparator(bytes memory message) internal pure returns (bytes memory) {
        bytes memory tampered = new bytes(message.length);
        for (uint i = 0; i < message.length; i++) {
            tampered[i] = message[i];
        }
        
        // Replace the first 32 bytes (domain separator) with wrong value
        bytes32 wrongDomain = keccak256("WrongDomain");
        for (uint i = 0; i < 32; i++) {
            tampered[i] = bytes1(uint8(wrongDomain[i]));
        }
        
        return tampered;
    }
    
    // ============================================================================
    // REGISTRATION INTENT TESTS - ALL ACTORS
    // ============================================================================
    
    function testSubmitRegistrationIntent_AllActors_Success() public {
        // Load comprehensive test vectors
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Find the registration intent vector for this actor
            string memory vectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            
            // Parse addresses from the test vector
            address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_address")));
            address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_fingerprint")));
            uint256 testETHNonce = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_nonce")));
            
            // Verify test vector matches actor config
            assertEq(testETHAddress, actor.ethAddress, string.concat("Test vector ETH address should match actor config for ", actorName));
            assertEq(testPQFingerprint, actor.pqFingerprint, string.concat("Test vector PQ fingerprint should match actor config for ", actorName));
            
            // Load the base PQ message and signature from test vector
            bytes memory basePQMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".base_pq_message")));
            bytes memory pqSignatureSalt = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_signature.salt")));
            uint256[] memory pqSignatureCs1 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_signature.cs1"));
            uint256[] memory pqSignatureCs2 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_signature.cs2"));
            uint256 pqSignatureHint = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_signature.hint")));
            
            // Recover the ETH address from the signature (as the contract does)
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_message")));
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.v"))));
            uint256 rDecimal = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.r")));
            uint256 sDecimal = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.s")));
            bytes32 r = bytes32(rDecimal);
            bytes32 s = bytes32(sDecimal);
            
            // Mock the Epervier verifier to return the correct fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector, basePQMessage, pqSignatureSalt, pqSignatureCs1, pqSignatureCs2, pqSignatureHint),
                abi.encode(actor.pqFingerprint)
            );
            
            // Submit registration intent
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Check both ETH and PQ nonces after submission
            assertEq(registry.ethNonces(actor.ethAddress), 1, string.concat("ETH nonce should be incremented for ", actorName));
            assertEq(registry.pqKeyNonces(actor.pqFingerprint), 1, string.concat("PQ nonce should be incremented for ", actorName));
        }
    }
    
    function testSubmitRegistrationIntent_MessageValidation_AllActors() public {
        // Load comprehensive test vectors
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Find the registration intent vector for this actor
            string memory vectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            
            // Mock the Epervier verifier to return the correct fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // Load the ETH intent message and signature
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_message")));
            uint8 v2 = uint8(vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.v"))));
            
            // Convert decimal r and s values to hex format for bytes32 parsing
            uint256 rDecimal2 = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.r")));
            uint256 sDecimal2 = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.s")));
            bytes32 r2 = bytes32(rDecimal2);
            bytes32 s2 = bytes32(sDecimal2);
            
            // Test 1: Tamper with ETH address in the message (flip a bit)
            bytes memory tamperedMessage = tamperWithAddress(ethIntentMessage, 32, 0); // Flip first bit of address
            vm.expectRevert("Expected pattern not found in message");
            registry.submitRegistrationIntent(tamperedMessage, v2, r2, s2);
            
            // Test 2: Tamper with PQ fingerprint in the message (flip a bit)
            bytes memory tamperedMessage2 = tamperWithAddress(ethIntentMessage, 64, 0); // Flip first bit of fingerprint
            vm.expectRevert("Expected pattern not found in message");
            registry.submitRegistrationIntent(tamperedMessage2, v2, r2, s2);
            
            // Test 3: Tamper with domain separator
            bytes memory tamperedMessage3 = tamperWithDomainSeparator(ethIntentMessage);
            vm.expectRevert("Expected pattern not found in message");
            registry.submitRegistrationIntent(tamperedMessage3, v2, r2, s2);
            
            console.log(string.concat("+ Message validation tests successful for ", actorName));
        }
    }
    
    function testSubmitRegistrationIntent_InvalidSignatures_AllActors() public {
        // Load comprehensive test vectors
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Find the registration intent vector for this actor
            string memory vectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_message")));
            
            // Test 1: Invalid ETH signature (zero components)
            (uint8 v, bytes32 r, bytes32 s) = createInvalidSignature();
            vm.expectRevert("ERR1: Invalid ETH signature");
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Test 2: Invalid ETH signature (wrong signer)
            // Create signature with wrong private key
            uint256 wrongPrivateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
            (v, r, s) = vm.sign(wrongPrivateKey, keccak256(ethIntentMessage));
            vm.expectRevert("ERR3: ETH signature must be from intent address");
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            console.log(string.concat("+ Invalid signature tests successful for ", actorName));
        }
    }
    
    function testSubmitRegistrationIntent_NonceValidation_AllActors() public {
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Load test data for this actor
            string memory jsonData = vm.readFile(string.concat("test/test_vectors/", actorName, "_test_vector.json"));
            
            // Mock the Epervier verifier to return the correct fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_message"));
            bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_signature"));
            (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
            
            // Submit first intent successfully
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Test: Try to submit again with same nonce (should fail)
            vm.expectRevert("ERR6: Invalid ETH nonce in submitRegistrationIntent");
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            console.log(string.concat("+ Nonce validation tests successful for ", actorName));
        }
    }
    
    function testSubmitRegistrationIntent_ConflictPrevention_AllActors() public {
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Load test data for this actor
            string memory jsonData = vm.readFile(string.concat("test/test_vectors/", actorName, "_test_vector.json"));
            
            // Mock the Epervier verifier to return the correct fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_message"));
            bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_signature"));
            (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
            
            // Complete registration first
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.pq_confirm_message"));
            bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.epervier_salt"));
            uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs1");
            uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs2");
            uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration.epervier_hint"));
            registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            // Test: Try to register again (should fail - already registered)
            vm.expectRevert("ERR5: Epervier key already registered");
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            console.log(string.concat("+ Conflict prevention tests successful for ", actorName));
        }
    }
    
    // ============================================================================
    // REGISTRATION CONFIRMATION TESTS - ALL ACTORS
    // ============================================================================
    
    function testConfirmRegistration_AllActors_Valid() public {
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Load test data for this actor
            string memory jsonData = vm.readFile(string.concat("test/test_vectors/", actorName, "_test_vector.json"));
            
            // Mock the Epervier verifier for both intent and confirmation
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // First submit a registration intent
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_message"));
            bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_signature"));
            (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Load the real PQ confirmation message from test vector
            bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.pq_confirm_message"));
            bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.epervier_salt"));
            uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs1");
            uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs2");
            uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration.epervier_hint"));
            
            // Expect the event to be emitted
            vm.expectEmit(true, true, false, true);
            emit RegistrationConfirmed(actor.ethAddress, actor.pqFingerprint);
            
            // Confirm registration with real data
            registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            // Verify registration was completed
            assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, string.concat("PQ fingerprint should be mapped to ETH address for ", actorName));
            assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, string.concat("ETH address should be mapped to PQ fingerprint for ", actorName));
            
            // Verify intent was cleared
            (address pqFingerprint2, bytes memory intentMessage2, uint256 timestamp2) = registry.pendingIntents(actor.ethAddress);
            assertEq(timestamp2, 0, string.concat("Intent should be cleared for ", actorName));
            assertEq(registry.pqFingerprintToPendingIntentAddress(actor.pqFingerprint), address(0), string.concat("Bidirectional mapping should be cleared for ", actorName));
            
            // Verify nonces were incremented
            assertEq(registry.ethNonces(actor.ethAddress), 2, string.concat("ETH nonce should be incremented again for ", actorName));
            
            console.log(string.concat("+ Registration confirmation successful for ", actorName));
        }
    }
    
    function testConfirmRegistration_MessageValidation_AllActors() public {
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Load test data for this actor
            string memory jsonData = vm.readFile(string.concat("test/test_vectors/", actorName, "_test_vector.json"));
            
            // Mock the Epervier verifier
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // First submit a registration intent
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_message"));
            bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_signature"));
            (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Load the real PQ confirmation message
            bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.pq_confirm_message"));
            bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.epervier_salt"));
            uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs1");
            uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs2");
            uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration.epervier_hint"));
            
            // Test 1: Tamper with ETH address in confirmation message
            bytes memory tamperedMessage = tamperWithAddress(pqConfirmMessage, 32, 0);
            vm.expectRevert("Expected pattern not found in message");
            registry.confirmRegistration(tamperedMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            // Test 2: Tamper with PQ fingerprint in confirmation message
            bytes memory tamperedMessage2 = tamperWithAddress(pqConfirmMessage, 64, 0);
            vm.expectRevert("Expected pattern not found in message");
            registry.confirmRegistration(tamperedMessage2, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            // Test 3: Tamper with domain separator in confirmation message
            bytes memory tamperedMessage3 = tamperWithDomainSeparator(pqConfirmMessage);
            vm.expectRevert("Expected pattern not found in message");
            registry.confirmRegistration(tamperedMessage3, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            console.log(string.concat("+ Confirmation message validation tests successful for ", actorName));
        }
    }
    
    function testConfirmRegistration_IntentValidation_AllActors() public {
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Load test data for this actor
            string memory jsonData = vm.readFile(string.concat("test/test_vectors/", actorName, "_test_vector.json"));
            
            // Mock the Epervier verifier
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // Load confirmation data
            bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.pq_confirm_message"));
            bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.epervier_salt"));
            uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs1");
            uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs2");
            uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration.epervier_hint"));
            
            // Test: Try to confirm without submitting intent first
            vm.expectRevert("No pending intent found for PQ fingerprint");
            registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            console.log(string.concat("+ Intent validation tests successful for ", actorName));
        }
    }
    
    // ============================================================================
    // COMPLETE REGISTRATION FLOW TESTS - ALL ACTORS
    // ============================================================================
    
    function testCompleteRegistrationFlow_AllActors() public {
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Load test data for this actor
            string memory jsonData = vm.readFile(string.concat("test/test_vectors/", actorName, "_test_vector.json"));
            
            // Mock the Epervier verifier to return the correct fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // Step 1: Submit registration intent
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_message"));
            bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.eth_intent_signature"));
            (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
            
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Verify intent was created
            (address pqFingerprint, , uint256 timestamp) = registry.pendingIntents(actor.ethAddress);
            assertEq(pqFingerprint, actor.pqFingerprint, string.concat("Intent should be created for ", actorName));
            assertGt(timestamp, 0, string.concat("Intent timestamp should be set for ", actorName));
            
            // Step 2: Confirm registration
            bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.pq_confirm_message"));
            bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration.epervier_salt"));
            uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs1");
            uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration.epervier_cs2");
            uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration.epervier_hint"));
            
            registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
            
            // Verify final state
            assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, string.concat("Final mapping should be correct for ", actorName));
            assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, string.concat("Final reverse mapping should be correct for ", actorName));
            
            // Verify intent was cleared
            (, , uint256 finalTimestamp) = registry.pendingIntents(actor.ethAddress);
            assertEq(finalTimestamp, 0, string.concat("Intent should be cleared after confirmation for ", actorName));
            
            console.log(string.concat("+ Complete registration flow successful for ", actorName));
        }
    }
} 