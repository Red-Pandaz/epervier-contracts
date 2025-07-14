// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "./PQRegistryTestSetup.sol";
import "../src/interfaces/IPQERC721.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract PQRegistryBasicTests is PQRegistryTestSetup {
    using ECDSA for bytes32;
    using Strings for string;
    
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
    event ChangeETHAddressIntentSubmitted(address indexed pqFingerprint, address indexed newETHAddress, uint256 ethNonce);
    
    function setUp() public override {
        super.setUp();
        
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
    
    // Helper function to register an actor (used by other tests)
    function registerActor(Actor memory actor, string memory actorName) internal {
        // Load registration vectors
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmationJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Find the registration intent vector for this actor
        uint256 actorIndex = 0;
        for (uint i = 0; i < actorNames.length; i++) {
            if (keccak256(bytes(actorNames[i])) == keccak256(bytes(actorName))) {
                actorIndex = i;
                break;
            }
        }
        
        string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(actorIndex), "]");
        string memory confirmationVectorPath = string.concat(".registration_confirmation[", vm.toString(actorIndex), "]");
        
        // Load intent data
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(intentVectorPath, ".eth_message")));
        uint8 vIntent = uint8(vm.parseUint(vm.parseJsonString(jsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
        uint256 rIntentDecimal = vm.parseUint(vm.parseJsonString(jsonData, string.concat(intentVectorPath, ".eth_signature.r")));
        uint256 sIntentDecimal = vm.parseUint(vm.parseJsonString(jsonData, string.concat(intentVectorPath, ".eth_signature.s")));
        bytes32 rIntent = bytes32(rIntentDecimal);
        bytes32 sIntent = bytes32(sIntentDecimal);
        
        // Mock the Epervier verifier for intent
        // vm.mockCall(
        //     address(epervierVerifier),
        //     abi.encodeWithSelector(epervierVerifier.recover.selector),
        //     abi.encode(actor.pqFingerprint)
        // );
        
        // Submit registration intent
        registry.submitRegistrationIntent(ethIntentMessage, vIntent, rIntent, sIntent);
        // vm.clearMockedCalls();
        
        // Load confirmation data
        bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_message")));
        bytes memory confirmationSalt = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.salt")));
        uint256 confirmationHint = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.hint")));
        
        string memory confirmationCs1Path = string.concat(confirmationVectorPath, ".pq_signature.cs1");
        uint256[] memory confirmationCs1 = new uint256[](32);
        for (uint j = 0; j < 32; j++) {
            confirmationCs1[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs1Path, "[", vm.toString(j), "]")));
        }
        
        string memory confirmationCs2Path = string.concat(confirmationVectorPath, ".pq_signature.cs2");
        uint256[] memory confirmationCs2 = new uint256[](32);
        for (uint j = 0; j < 32; j++) {
            confirmationCs2[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs2Path, "[", vm.toString(j), "]")));
        }
        
        // Mock the Epervier verifier for confirmation
        // vm.mockCall(
        //     address(epervierVerifier),
        //     abi.encodeWithSelector(epervierVerifier.recover.selector),
        //     abi.encode(actor.pqFingerprint)
        // );
        
        // Confirm registration
        registry.confirmRegistration(pqConfirmationMessage, confirmationSalt, confirmationCs1, confirmationCs2, confirmationHint);
        // vm.clearMockedCalls();
    }

    // ============================================================================
    // REGISTRATION TESTS
    // ============================================================================
    
    function testSubmitRegistrationIntent_Success() public {
        // Use Alice's data from the centralized config
        Actor memory alice = getActor("alice");
        
        // Load test data from the comprehensive registration vectors
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        
        // Parse addresses from the test vector directly
        address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, ".registration_intent[0].eth_address"));
        address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".registration_intent[0].pq_fingerprint"));
        
        // Verify the test vector matches our actor config
        assertEq(testETHAddress, alice.ethAddress, "Test vector ETH address should match actor config");
        assertEq(testPQFingerprint, alice.pqFingerprint, "Test vector PQ fingerprint should match actor config");
        
        // Parse signature components for registration intent
        bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].pq_signature.salt"));
        uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, ".registration_intent[0].pq_signature.cs1");
        uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, ".registration_intent[0].pq_signature.cs2");
        uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].pq_signature.hint"));
        
        // Real Epervier verification - no mock needed
        
        // Load the real ETH intent message from test vector (now without domain separator)
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse the ETH intent message to extract components for EIP712 signing
        // Note: ETH message no longer contains domain separator in content
        (uint256 ethNonce, bytes memory salt, uint256[] memory cs1Array, uint256[] memory cs2Array, uint256 hint, bytes memory basePQMessage) = 
            messageParser.parseETHRegistrationIntentMessage(ethIntentMessage);
        
        // Convert dynamic arrays to fixed-size arrays for EIP712 struct hash
        uint256[32] memory cs1;
        uint256[32] memory cs2;
        for (uint256 i = 0; i < 32; i++) {
            cs1[i] = cs1Array[i];
            cs2[i] = cs2Array[i];
        }
        
        // Use the ETH signature from the test vector (already generated with EIP712)
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.s"));
        
        // Check initial nonces before submitting intent
        assertEq(registry.ethNonces(alice.ethAddress), 0, "Initial ETH nonce should be 0");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 0, "Initial PQ nonce should be 0");

        // Submit registration intent with real data
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Verify intent was created
        (address pqFingerprint, bytes memory intentMessage, uint256 timestamp) = registry.pendingIntents(alice.ethAddress);
        assertEq(pqFingerprint, alice.pqFingerprint, "PQ fingerprint should match");
        assertEq(registry.ethNonces(alice.ethAddress), 1, "ETH nonce should be incremented");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 1, "PQ nonce should be incremented");
        assertGt(timestamp, 0, "Timestamp should be set");
        
        // Verify bidirectional mapping
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), alice.ethAddress, "Bidirectional mapping should be set");
    }

    function testSubmitRegistrationIntent_AllActors_Success() public {
        // Load comprehensive test vectors
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        
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
            
            // Load the ETH intent message from test vector (now without domain separator)
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_message")));
            
            // Parse the ETH intent message to extract components for EIP712 signing
            // Note: ETH message no longer contains domain separator in content
            (uint256 ethNonce2, bytes memory salt2, uint256[] memory cs1Array2, uint256[] memory cs2Array2, uint256 hint2, bytes memory basePQMessage2) = 
                messageParser.parseETHRegistrationIntentMessage(ethIntentMessage);
            
            // Convert dynamic arrays to fixed-size arrays for EIP712 struct hash
            uint256[32] memory cs1_2;
            uint256[32] memory cs2_2;
            for (uint256 j = 0; j < 32; j++) {
                cs1_2[j] = cs1Array2[j];
                cs2_2[j] = cs2Array2[j];
            }
            
            // Use the ETH signature from the test vector (already generated with EIP712)
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.v"))));
            bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.r")));
            bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.s")));
            
            // Mock the Epervier verifier to return the correct fingerprint
            // vm.mockCall(
            //     address(epervierVerifier),
            //     abi.encodeWithSelector(epervierVerifier.recover.selector),
            //     abi.encode(actor.pqFingerprint)
            // );
            
            // Submit registration intent
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Check both ETH and PQ nonces after submission
            assertEq(registry.ethNonces(actor.ethAddress), 1, string.concat("ETH nonce should be incremented for ", actorName));
            assertEq(registry.pqKeyNonces(actor.pqFingerprint), 1, string.concat("PQ nonce should be incremented for ", actorName));
        }
    }
    
    function testConfirmRegistration_Success() public {
        // Use Alice's data
        Actor memory alice = getActor("alice");
        
        // First submit registration intent
        testSubmitRegistrationIntent_Success();
        
        // Load confirmation test data
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Parse addresses from the test vector
        address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, ".registration_confirmation[0].eth_address"));
        address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_fingerprint"));
        
        // Verify the test vector matches our actor config
        assertEq(testETHAddress, alice.ethAddress, "Test vector ETH address should match actor config");
        assertEq(testPQFingerprint, alice.pqFingerprint, "Test vector PQ fingerprint should match actor config");
        
        // Parse signature components for confirmation
        bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        // Real Epervier verification - no mock needed
        
        // Load the real PQ confirmation message from test vector
        bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_message"));
        
        // Confirm registration with real data
        registry.confirmRegistration(pqConfirmationMessage, testSalt, testCs1, testCs2, testHint);
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "Registration should be complete");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "Registration should be complete");
        
        // Verify pending intent was cleared
        (address pendingFingerprint, , ) = registry.pendingIntents(alice.ethAddress);
        assertEq(pendingFingerprint, address(0), "Pending intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), address(0), "Pending intent mapping should be cleared");
    }

    function testConfirmRegistration_AllActors_Success() public {
        // Load comprehensive test vectors
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // First submit registration intent for this actor
            string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
            string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_message")));
            
            // Parse the ETH intent message to extract components for EIP712 signing
            // Note: ETH message no longer contains domain separator in content
            (uint256 ethNonce3, bytes memory salt3, uint256[] memory cs1Array3, uint256[] memory cs2Array3, uint256 hint3, bytes memory basePQMessage3) = 
                messageParser.parseETHRegistrationIntentMessage(ethIntentMessage);
            
            // Convert dynamic arrays to fixed-size arrays for EIP712 struct hash
            uint256[32] memory cs1_3;
            uint256[32] memory cs2_3;
            for (uint256 j = 0; j < 32; j++) {
                cs1_3[j] = cs1Array3[j];
                cs2_3[j] = cs2Array3[j];
            }
            
            // Use the ETH signature from the test vector (already generated with EIP712)
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
            bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.r")));
            bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.s")));
            
            // Mock the Epervier verifier for intent
            // vm.mockCall(
            //     address(epervierVerifier),
            //     abi.encodeWithSelector(epervierVerifier.recover.selector),
            //     abi.encode(actor.pqFingerprint)
            // );
            
            // Submit registration intent
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            // vm.clearMockedCalls();
            
            // Find the confirmation vector for this actor
            string memory confirmationVectorPath = string.concat(".registration_confirmation[", vm.toString(i), "]");
            
            // Parse addresses from the test vector
            address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(confirmationVectorPath, ".eth_address")));
            address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(confirmationVectorPath, ".pq_fingerprint")));
            
            // Verify test vector matches actor config
            assertEq(testETHAddress, actor.ethAddress, string.concat("Test vector ETH address should match actor config for ", actorName));
            assertEq(testPQFingerprint, actor.pqFingerprint, string.concat("Test vector PQ fingerprint should match actor config for ", actorName));
            
            // Parse signature components for confirmation
            bytes memory confirmationSalt = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(confirmationVectorPath, ".pq_signature.salt")));
            uint256[] memory confirmationCs1 = vm.parseJsonUintArray(jsonData, string.concat(confirmationVectorPath, ".pq_signature.cs1"));
            uint256[] memory confirmationCs2 = vm.parseJsonUintArray(jsonData, string.concat(confirmationVectorPath, ".pq_signature.cs2"));
            uint256 confirmationHint = vm.parseUint(vm.parseJsonString(jsonData, string.concat(confirmationVectorPath, ".pq_signature.hint")));
            
            // Mock the Epervier verifier for confirmation
            // vm.mockCall(
            //     address(epervierVerifier),
            //     abi.encodeWithSelector(epervierVerifier.recover.selector),
            //     abi.encode(actor.pqFingerprint)
            // );
            
            // Load the real PQ confirmation message from test vector
            bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(confirmationVectorPath, ".pq_message")));
            
            // Debug: Print the PQ message and signature components
            console.log("=== DEBUG PQ RECOVERY ===");
            console.log("PQ Message length:", pqConfirmationMessage.length);
            // Extract first 64 bytes manually
            bytes memory first64Bytes = new bytes(64);
            for (uint i = 0; i < 64 && i < pqConfirmationMessage.length; i++) {
                first64Bytes[i] = pqConfirmationMessage[i];
            }
            console.log("PQ Message (first 64 bytes):", string(abi.encodePacked(first64Bytes)));
            console.log("Salt length:", confirmationSalt.length);
            console.log("Salt (hex):", vm.toString(confirmationSalt));
            console.log("CS1[0]:", confirmationCs1[0]);
            console.log("CS2[0]:", confirmationCs2[0]);
            console.log("Hint:", confirmationHint);
            console.log("Expected fingerprint:", actor.pqFingerprint);
            
            // Confirm registration
            registry.confirmRegistration(pqConfirmationMessage, confirmationSalt, confirmationCs1, confirmationCs2, confirmationHint);
            // vm.clearMockedCalls();

            // Debug output: print expected and actual PQ fingerprint
            address actualPQFingerprint = registry.addressToEpervierKey(actor.ethAddress);
            console.log("Expected PQ fingerprint:", actor.pqFingerprint);
            console.log("Recovered PQ fingerprint:", actualPQFingerprint);

            // Verify registration was completed
            assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, string.concat("Registration should be complete for ", actorName));
            assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, string.concat("Registration should be complete for ", actorName));
        }
    }
} 