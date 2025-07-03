// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract MockConsole {
    function log(string memory) external {}
    function log(string memory, uint256) external {}
    function log(string memory, address) external {}
}

contract PQRegistryRegistrationTest is Test {
    using ECDSA for bytes32;
    using Strings for string;
    
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
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
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        
        // Deploy mock contracts for the dependencies
        MockConsole mockConsole = new MockConsole();
        
        registry = new PQRegistry(
            address(epervierVerifier)
        );
        
        // Load actor data from centralized config
        loadActorsConfig();
        
        // Mock the Epervier verifier to return the correct fingerprint for each actor
        // We'll set up specific mocks in each test as needed
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
    
    // ============================================================================
    // SUCCESS TESTS
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
        
        // Load the real ETH intent message from test vector
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse signature from test vector (EIP-712 signature)
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
            
            // Load the ETH intent message from test vector
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_message")));
            
            // Parse signature from test vector (EIP-712 signature)
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.v"))));
            bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.r")));
            bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.s")));
            
            // Real Epervier verification - no mock needed
            
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
        
        // First submit a registration intent
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse the ETH intent message to extract components for EIP712 signing
        (uint256 ethNonce, bytes memory salt, uint256[] memory cs1Array, uint256[] memory cs2Array, uint256 hint, bytes memory basePQMessage) = 
            MessageParser.parseETHRegistrationIntentMessage(ethIntentMessage);
        
        // Convert dynamic arrays to fixed-size arrays for EIP712 struct hash
        uint256[32] memory cs1;
        uint256[32] memory cs2;
        for (uint256 i = 0; i < 32; i++) {
            cs1[i] = cs1Array[i];
            cs2[i] = cs2Array[i];
        }
        
        // Parse signature from test vector (EIP-712 signature)
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.s"));
        
        // Mock the Epervier verifier for intent submission
        // vm.mockCall(
        //     address(epervierVerifier),
        //     abi.encodeWithSelector(epervierVerifier.recover.selector),
        //     abi.encode(alice.pqFingerprint)
        // );
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Clear the mock
        // vm.clearMockedCalls();
        
        // Load the real PQ confirmation message from test vector
        string memory confirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".registration_confirmation[0].pq_message"));
        
        // Load the real signature components for confirmation
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        // Confirm registration with real data
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "PQ fingerprint should be mapped to ETH address");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "ETH address should be mapped to PQ fingerprint");
        
        // Verify intent was cleared
        (address pqFingerprint2, bytes memory intentMessage2, uint256 timestamp2) = registry.pendingIntents(alice.ethAddress);
        assertEq(timestamp2, 0, "Intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), address(0), "Bidirectional mapping should be cleared");
        
        // Verify nonces were incremented
        assertEq(registry.ethNonces(alice.ethAddress), 2, "ETH nonce should be incremented again");
    }
    
    function testConfirmRegistration_AllActors_Success() public {
        // Load comprehensive test vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Find the intent vector for this actor
            string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            
            // Parse intent data from the test vector
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_message")));
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
            uint256 rDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.r")));
            uint256 sDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.s")));
            bytes32 r = bytes32(rDecimal);
            bytes32 s = bytes32(sDecimal);
            
            // Mock the Epervier verifier for intent submission
            // vm.mockCall(
            //     address(epervierVerifier),
            //     abi.encodeWithSelector(epervierVerifier.recover.selector),
            //     abi.encode(actor.pqFingerprint)
            // );
            
            // Check initial nonces before submitting intent
            assertEq(registry.ethNonces(actor.ethAddress), 0, string.concat("Initial ETH nonce should be 0 for ", actorName));
            assertEq(registry.pqKeyNonces(actor.pqFingerprint), 0, string.concat("Initial PQ nonce should be 0 for ", actorName));
            
            // Submit registration intent
            registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
            
            // Verify intent was created
            (address pqFingerprint, bytes memory intentMessage, uint256 timestamp) = registry.pendingIntents(actor.ethAddress);
            assertEq(pqFingerprint, actor.pqFingerprint, string.concat("PQ fingerprint should match for ", actorName));
            assertEq(registry.ethNonces(actor.ethAddress), 1, string.concat("ETH nonce should be incremented for ", actorName));
            assertEq(registry.pqKeyNonces(actor.pqFingerprint), 1, string.concat("PQ nonce should be incremented for ", actorName));
            assertGt(timestamp, 0, string.concat("Timestamp should be set for ", actorName));
            
            // Find the confirmation vector for this actor
            string memory confirmVectorPath = string.concat(".registration_confirmation[", vm.toString(i), "]");
            
            // Parse confirmation data from the test vector
            bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_message")));
            bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.salt")));
            uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.cs1"));
            uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.cs2"));
            uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.hint")));
            
            // Mock the Epervier verifier for confirmation
            // vm.mockCall(
            //     address(epervierVerifier),
            //     abi.encodeWithSelector(epervierVerifier.recover.selector),
            //     abi.encode(actor.pqFingerprint)
            // );
            
            // Confirm registration
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
            assertEq(registry.pqKeyNonces(actor.pqFingerprint), 2, string.concat("PQ nonce should be incremented again for ", actorName));
            
            console.log(string.concat("Completed registration flow for ", actorName));
        }
        
        console.log("All 10 actors registration flows completed successfully!");
    }
    
    function testRemoveIntentByETH_AllActors_Success() public {
        // Load intent and removal vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory removalJsonData = vm.readFile("test/test_vectors/register/registration_eth_removal_vectors.json");

        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);

            // Find the intent vector for this actor
            string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            // Find the removal vector for this actor
            string memory removalVectorPath = string.concat(".registration_eth_removal[", vm.toString(i), "]");

            // Parse intent data from the test vector
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_message")));
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
            uint256 rDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.r")));
            uint256 sDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.s")));
            bytes32 r = bytes32(rDecimal);
            bytes32 s = bytes32(sDecimal);

            // Submit the registration intent
            registry.submitRegistrationIntent(
                ethIntentMessage,
                v,
                r,
                s
            );

            // Parse removal data from the test vector
            bytes memory ethRemoveMessage = vm.parseBytes(vm.parseJsonString(removalJsonData, string.concat(removalVectorPath, ".eth_message")));
            uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(removalJsonData, string.concat(removalVectorPath, ".eth_signature.v"))));
            uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(removalJsonData, string.concat(removalVectorPath, ".eth_signature.r")));
            uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(removalJsonData, string.concat(removalVectorPath, ".eth_signature.s")));
            bytes32 rRemove = bytes32(rRemoveDecimal);
            bytes32 sRemove = bytes32(sRemoveDecimal);

            // Get the PQ fingerprint from the intent before removing it
            (address storedPQFingerprint, , ) = registry.pendingIntents(actor.ethAddress);
            console.log("Stored PQ fingerprint:", storedPQFingerprint);

            // Remove the intent
            registry.removeRegistrationIntentByETH(ethRemoveMessage, vRemove, rRemove, sRemove);

            // Verify the intent mapping is cleared
            (address pqFingerprint, , uint256 timestamp) = registry.pendingIntents(actor.ethAddress);
            assertEq(pqFingerprint, address(0), "PQ fingerprint should be zero address after removal");
            assertEq(timestamp, 0, "Timestamp should be zero after removal");

            // Check the bidirectional mapping using the PQ fingerprint that was stored in the intent
            address ethAddress = registry.pqFingerprintToPendingIntentAddress(storedPQFingerprint);
            console.log("ETH address for stored PQ fingerprint:", ethAddress);
            assertEq(ethAddress, address(0), "ETH address should be zero address after removal");

            console.log("Intent created and removed for", actorName);
        }
    }

    function testRemoveIntentByPQ_AllActors_Success() public {
        // Load intent and PQ removal vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory pqRemovalJsonData = vm.readFile("test/test_vectors/register/registration_pq_removal_vectors.json");

        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);

            // Find the intent vector for this actor
            string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            // Find the PQ removal vector for this actor
            string memory pqRemovalVectorPath = string.concat(".registration_pq_removal[", vm.toString(i), "]");

            // Parse intent data from the test vector
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_message")));
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
            uint256 rDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.r")));
            uint256 sDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.s")));
            bytes32 r = bytes32(rDecimal);
            bytes32 s = bytes32(sDecimal);

            // Log PQ nonce before submitting registration intent
            console.log("[", actorName, "] PQ nonce before intent:", registry.pqKeyNonces(actor.pqFingerprint));

            // Submit the registration intent
            registry.submitRegistrationIntent(
                ethIntentMessage,
                v,
                r,
                s
            );

            // Log PQ nonce after submitting registration intent
            console.log("[", actorName, "] PQ nonce after intent:", registry.pqKeyNonces(actor.pqFingerprint));

            // Get the PQ fingerprint from the intent before removing it
            (address storedPQFingerprint, , ) = registry.pendingIntents(actor.ethAddress);

            // Parse PQ removal data from the test vector
            bytes memory pqRemoveMessage = vm.parseBytes(vm.parseJsonString(pqRemovalJsonData, string.concat(pqRemovalVectorPath, ".pq_message")));
            bytes memory salt = vm.parseBytes(vm.parseJsonString(pqRemovalJsonData, string.concat(pqRemovalVectorPath, ".pq_signature.salt")));
            uint256[] memory cs1 = vm.parseJsonUintArray(pqRemovalJsonData, string.concat(pqRemovalVectorPath, ".pq_signature.cs1"));
            uint256[] memory cs2 = vm.parseJsonUintArray(pqRemovalJsonData, string.concat(pqRemovalVectorPath, ".pq_signature.cs2"));
            uint256 hint = vm.parseUint(vm.parseJsonString(pqRemovalJsonData, string.concat(pqRemovalVectorPath, ".pq_signature.hint")));

            // Log PQ nonce before PQ removal
            console.log("[", actorName, "] PQ nonce before PQ removal:", registry.pqKeyNonces(actor.pqFingerprint));

            // Remove the intent by PQ
            registry.removeRegistrationIntentByPQ(pqRemoveMessage, salt, cs1, cs2, hint);

            // Log PQ nonce after PQ removal
            console.log("[", actorName, "] PQ nonce after PQ removal:", registry.pqKeyNonces(actor.pqFingerprint));

            // Verify the intent mapping is cleared
            (address pqFingerprint, , uint256 timestamp) = registry.pendingIntents(actor.ethAddress);
            assertEq(pqFingerprint, address(0), "PQ fingerprint should be zero address after PQ removal");
            assertEq(timestamp, 0, "Timestamp should be zero after PQ removal");

            // Check the bidirectional mapping using the PQ fingerprint that was stored in the intent
            address ethAddress = registry.pqFingerprintToPendingIntentAddress(storedPQFingerprint);
            assertEq(ethAddress, address(0), "ETH address should be zero address after PQ removal");

            console.log("Intent created and PQ-removed for", actorName);
        }
    }
    
} 