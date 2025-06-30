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

contract PQRegistryUnregistrationTest is Test {
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
            address(epervierVerifier),
            address(mockConsole)
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
    
    function testSubmitUnregistrationIntent_Success() public {
        // Use Alice's data from the centralized config
        Actor memory alice = getActor("alice");
        
        // First register Alice so she can be unregistered
        registerActor(alice, "alice");
        
        // Log the registered ETH address and Alice's ETH address
        emit log_address(registry.epervierKeyToAddress(alice.pqFingerprint));
        emit log_address(alice.ethAddress);
        
        // Load unregistration intent vectors
        string memory jsonData = vm.readFile("test/test_vectors/unregister/unregistration_intent_vectors.json");
        
        // Parse addresses from the test vector
        address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, ".unregistration_intent[0].eth_address"));
        address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".unregistration_intent[0].pq_fingerprint"));
        
        // Verify the test vector matches our actor config
        assertEq(testETHAddress, alice.ethAddress, "Test vector ETH address should match actor config");
        assertEq(testPQFingerprint, alice.pqFingerprint, "Test vector PQ fingerprint should match actor config");
        
        // Parse signature components
        bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".unregistration_intent[0].pq_signature.salt"));
        uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, ".unregistration_intent[0].pq_signature.cs1");
        uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, ".unregistration_intent[0].pq_signature.cs2");
        uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, ".unregistration_intent[0].pq_signature.hint"));
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // Load the real PQ message from test vector
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".unregistration_intent[0].pq_message"));
        
        // Create a dummy public key
        uint256[2] memory publicKey = [uint256(1), uint256(2)];
        
        // Print the first 100 bytes of the PQ message for debugging
        bytes memory pqMsg = pqMessage;
        bytes memory first100 = new bytes(pqMsg.length < 100 ? pqMsg.length : 100);
        for (uint j = 0; j < first100.length; j++) {
            first100[j] = pqMsg[j];
        }
        console.logBytes(first100);
        // Submit unregistration intent with real data
        registry.submitUnregistrationIntent(pqMessage, testSalt, testCs1, testCs2, testHint, publicKey);
        
        // Verify ETH nonce was incremented
        assertEq(registry.ethNonces(alice.ethAddress), 3, "ETH nonce should be incremented");
        
        // Verify registration is still intact
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "Registration should still be active");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "Registration should still be active");
    }
    
    function testSubmitUnregistrationIntent_AllActors_Success() public {
        // Load comprehensive test vectors
        string memory jsonData = vm.readFile("test/test_vectors/unregister/unregistration_intent_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // First register the actor
            registerActor(actor, actorName);
            
            // Log the registered ETH address and actor's ETH address
            emit log_address(registry.epervierKeyToAddress(actor.pqFingerprint));
            emit log_address(actor.ethAddress);
            
            // Find the intent vector for this actor
            string memory vectorPath = string.concat(".unregistration_intent[", vm.toString(i), "]");
            
            // Parse addresses from the test vector
            address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_address")));
            address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_fingerprint")));
            
            // Verify the test vector matches our actor config
            assertEq(testETHAddress, actor.ethAddress, string.concat("Test vector ETH address should match actor config for ", actorName));
            assertEq(testPQFingerprint, actor.pqFingerprint, string.concat("Test vector PQ fingerprint should match actor config for ", actorName));
            
            // Parse signature components
            bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_signature.salt")));
            uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_signature.cs1"));
            uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_signature.cs2"));
            uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_signature.hint")));
            
            // Mock the Epervier verifier to return the actor's fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // Load the real PQ message from test vector
            bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_message")));
            
            // Create a dummy public key
            uint256[2] memory publicKey = [uint256(1), uint256(2)];
            
            // Print the first 100 bytes of the PQ message for debugging
            bytes memory pqMsg = pqMessage;
            bytes memory first100 = new bytes(pqMsg.length < 100 ? pqMsg.length : 100);
            for (uint j = 0; j < first100.length; j++) {
                first100[j] = pqMsg[j];
            }
            console.logBytes(first100);
            // Submit unregistration intent with real data
            registry.submitUnregistrationIntent(pqMessage, testSalt, testCs1, testCs2, testHint, publicKey);
            
            // Verify ETH nonce was incremented
            assertEq(registry.ethNonces(actor.ethAddress), 3, string.concat("ETH nonce should be incremented for ", actorName));
            
            // Verify registration is still intact
            assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, string.concat("Registration should still be active for ", actorName));
            assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, string.concat("Registration should still be active for ", actorName));
            
            // Clear the mock for the next iteration
            vm.clearMockedCalls();
        }
    }
    
    // ============================================================================
    // UNREGISTRATION INTENT REMOVAL TESTS (PQ-controlled only)
    // ============================================================================
    
    function testRemoveUnregistrationIntent_Success() public {
        // Use Alice's data from the centralized config
        Actor memory alice = getActor("alice");
        
        // First register Alice so she can be unregistered
        registerActor(alice, "alice");
        
        // Log the registered ETH address and Alice's ETH address
        emit log_address(registry.epervierKeyToAddress(alice.pqFingerprint));
        emit log_address(alice.ethAddress);
        
        // Submit unregistration intent first
        submitUnregistrationIntent(alice, 0);
        
        // Load PQ removal vectors from the correct file
        string memory jsonData = vm.readFile("test/test_vectors/unregister/unregistration_removal_vectors.json");
        
        // Parse addresses from the test vector
        address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, ".remove_intent[0].eth_address"));
        address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".remove_intent[0].pq_fingerprint"));
        
        // Verify the test vector matches our actor config
        assertEq(testETHAddress, alice.ethAddress, "Test vector ETH address should match actor config");
        assertEq(testPQFingerprint, alice.pqFingerprint, "Test vector PQ fingerprint should match actor config");
        
        // Parse signature components for PQ removal
        bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_intent[0].pq_remove_unregistration_intent.signature.salt"));
        uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, ".remove_intent[0].pq_remove_unregistration_intent.signature.cs1");
        uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, ".remove_intent[0].pq_remove_unregistration_intent.signature.cs2");
        uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_intent[0].pq_remove_unregistration_intent.signature.hint"));
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // Load the real PQ message from test vector
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_intent[0].pq_remove_unregistration_intent.message"));
        
        // Remove unregistration intent with PQ signature
        registry.removeUnregistrationIntent(pqMessage, testSalt, testCs1, testCs2, testHint);
        
        // Verify registration is still intact
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "Registration should still be active");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "Registration should still be active");
    }
    
    function testRemoveUnregistrationIntent_AllActors_Success() public {
        // Load comprehensive PQ removal vectors from the correct file
        string memory jsonData = vm.readFile("test/test_vectors/unregister/unregistration_removal_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // First register the actor
            registerActor(actor, actorName);
            
            // Log the registered ETH address and actor's ETH address
            emit log_address(registry.epervierKeyToAddress(actor.pqFingerprint));
            emit log_address(actor.ethAddress);
            
            // Submit unregistration intent first (needed for removal test)
            submitUnregistrationIntent(actor, i);
            
            // Find the removal vector for this actor
            string memory vectorPath = string.concat(".remove_intent[", vm.toString(i), "]");
            
            // Parse addresses from the test vector
            address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_address")));
            address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_fingerprint")));
            
            // Verify the test vector matches our actor config
            assertEq(testETHAddress, actor.ethAddress, string.concat("Test vector ETH address should match actor config for ", actorName));
            assertEq(testPQFingerprint, actor.pqFingerprint, string.concat("Test vector PQ fingerprint should match actor config for ", actorName));
            
            // Parse signature components
            bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_remove_unregistration_intent.signature.salt")));
            uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_remove_unregistration_intent.signature.cs1"));
            uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_remove_unregistration_intent.signature.cs2"));
            uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_remove_unregistration_intent.signature.hint")));
            
            // Mock the Epervier verifier to return the actor's fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // Load the real PQ removal message from test vector
            bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_remove_unregistration_intent.message")));
            
            // Debug: Print the first 100 bytes of the loaded message
            bytes memory first100 = new bytes(pqMessage.length < 100 ? pqMessage.length : 100);
            for (uint j = 0; j < first100.length; j++) {
                first100[j] = pqMessage[j];
            }
            console.logBytes(first100);
            // Debug: Print the expected pattern in hex
            bytes memory expectedPattern = bytes("Remove unregistration intent from ETH Address ");
            console.logBytes(expectedPattern);
            
            // Debug: Print the message length and first 50 bytes in hex
            console.log("Message length:", pqMessage.length);
            console.log("First 50 bytes:");
            for (uint j = 0; j < 50 && j < pqMessage.length; j++) {
                console.logBytes(abi.encodePacked(pqMessage[j]));
            }
            
            // Remove unregistration intent with PQ signature
            registry.removeUnregistrationIntent(pqMessage, testSalt, testCs1, testCs2, testHint);
            
            // Verify registration is still intact
            assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, string.concat("Registration should still be active for ", actorName));
            assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, string.concat("Registration should still be active for ", actorName));
            
            // Clear the mock for the next iteration
            vm.clearMockedCalls();
        }
    }
    
    // ============================================================================
    // UNREGISTRATION CONFIRMATION TESTS
    // ============================================================================
    
    function testConfirmUnregistration_AllActors_Success() public {
        // Load comprehensive unregistration confirmation vectors
        string memory jsonData = vm.readFile("test/test_vectors/unregister/unregistration_confirmation_vectors.json");
        
        for (uint i = 0; i < actorNames.length; i++) {
            string memory actorName = actorNames[i];
            Actor memory actor = getActor(actorName);
            
            // Reset contract state by redeploying for each actor
            MockConsole mockConsole = new MockConsole();
            
            registry = new PQRegistry(
                address(epervierVerifier),
                address(mockConsole)
            );
            
            // First register the actor
            registerActor(actor, actorName);
            
            // Submit unregistration intent first (needed for confirmation test)
            submitUnregistrationIntent(actor, i);
            
            // Find the confirmation vector for this actor using the correct index
            string memory vectorPath = string.concat(".unregistration_confirmation[", vm.toString(i), "]");
            
            // Parse addresses from the test vector
            address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_address")));
            address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_fingerprint")));
            
            // Verify the test vector matches our actor config
            assertEq(testETHAddress, actor.ethAddress, string.concat("Test vector ETH address should match actor config for ", actorName));
            assertEq(testPQFingerprint, actor.pqFingerprint, string.concat("Test vector PQ fingerprint should match actor config for ", actorName));
            
            // Parse ETH message and signature components
            bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_message")));
            uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.v"))));
            uint256 rDecimal = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.r")));
            uint256 sDecimal = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_signature.s")));
            bytes32 r = bytes32(rDecimal);
            bytes32 s = bytes32(sDecimal);
            
            // Mock the Epervier verifier to return the actor's fingerprint
            vm.mockCall(
                address(epervierVerifier),
                abi.encodeWithSelector(epervierVerifier.recover.selector),
                abi.encode(actor.pqFingerprint)
            );
            
            // Confirm unregistration
            registry.confirmUnregistration(ethMessage, v, r, s);
            
            // Verify registration has been removed
            assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), address(0), string.concat("Registration should be removed for ", actorName));
            assertEq(registry.addressToEpervierKey(actor.ethAddress), address(0), string.concat("Registration should be removed for ", actorName));
            
            // Verify unregistration intent has been cleared
            (uint256 timestamp,,) = registry.unregistrationIntents(actor.ethAddress);
            assertEq(timestamp, 0, string.concat("Unregistration intent should be cleared for ", actorName));
            
            // Clear the mock for the next iteration
            vm.clearMockedCalls();
        }
    }
    
    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    
    function registerActor(Actor memory actor, string memory actorName) internal {
        // Load registration intent vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Find the actor's index
        uint actorIndex = 0;
        for (uint i = 0; i < actorNames.length; i++) {
            if (keccak256(bytes(actorNames[i])) == keccak256(bytes(actorName))) {
                actorIndex = i;
                break;
            }
        }
        
        // Load intent data
        string memory intentPath = string.concat(".registration_intent[", vm.toString(actorIndex), "]");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentPath, ".eth_message")));
        
        // Parse signature components
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentPath, ".eth_signature.v"))));
        uint256 rDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentPath, ".eth_signature.r")));
        uint256 sDecimal = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentPath, ".eth_signature.s")));
        bytes32 r = bytes32(rDecimal);
        bytes32 s = bytes32(sDecimal);
        
        // Mock the Epervier verifier for intent submission
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(actor.pqFingerprint)
        );
        
        // Submit registration intent
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Clear the mock
        vm.clearMockedCalls();
        
        // Load confirmation data
        string memory confirmPath = string.concat(".registration_confirmation[", vm.toString(actorIndex), "]");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmPath, ".pq_message")));
        
        // Load confirmation signature components
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmPath, ".pq_signature.salt")));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmPath, ".pq_signature.cs1"));
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmPath, ".pq_signature.cs2"));
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJsonData, string.concat(confirmPath, ".pq_signature.hint")));
        
        // Mock the Epervier verifier for confirmation
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(actor.pqFingerprint)
        );
        
        // Confirm registration
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        
        // Clear the mock
        vm.clearMockedCalls();
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, "Registration should be completed");
        assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, "Registration should be completed");
    }
    
    function submitUnregistrationIntent(Actor memory actor, uint256 actorIndex) internal {
        // Load test data from the unregistration intent vectors
        string memory jsonData = vm.readFile("test/test_vectors/unregister/unregistration_intent_vectors.json");
        
        // Use the correct vector index for this actor
        string memory vectorPath = string.concat(".unregistration_intent[", vm.toString(actorIndex), "]");
        
        // Parse addresses from the test vector directly
        address testETHAddress = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".eth_address")));
        address testPQFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_fingerprint")));
        
        // Verify the test vector matches our actor config
        assertEq(testETHAddress, actor.ethAddress, "Test vector ETH address should match actor config");
        assertEq(testPQFingerprint, actor.pqFingerprint, "Test vector PQ fingerprint should match actor config");
        
        // Parse signature components for unregistration intent
        bytes memory testSalt = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_signature.salt")));
        uint256[] memory testCs1 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_signature.cs1"));
        uint256[] memory testCs2 = vm.parseJsonUintArray(jsonData, string.concat(vectorPath, ".pq_signature.cs2"));
        uint256 testHint = vm.parseUint(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_signature.hint")));
        
        // Mock the Epervier verifier to return the actor's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(actor.pqFingerprint)
        );
        
        // Load the real PQ message from test vector
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(vectorPath, ".pq_message")));
        
        // Create a dummy public key (this would normally be the actual public key)
        uint256[2] memory publicKey = [uint256(1), uint256(2)];
        
        // Check initial nonces before submitting intent
        assertEq(registry.ethNonces(actor.ethAddress), 2, "Initial ETH nonce should be 2 after registration");
        assertEq(registry.pqKeyNonces(actor.pqFingerprint), 2, "Initial PQ nonce should be 2 after registration");

        // Log the registered ETH address and actor's ETH address
        emit log_address(registry.epervierKeyToAddress(actor.pqFingerprint));
        emit log_address(actor.ethAddress);

        // Submit unregistration intent with real data
        registry.submitUnregistrationIntent(pqMessage, testSalt, testCs1, testCs2, testHint, publicKey);
        
        // Verify ETH nonce was incremented
        assertEq(registry.ethNonces(actor.ethAddress), 3, "ETH nonce should be incremented");
        
        // Verify registration is still intact
        assertEq(registry.epervierKeyToAddress(actor.pqFingerprint), actor.ethAddress, "Registration should still be active");
        assertEq(registry.addressToEpervierKey(actor.ethAddress), actor.pqFingerprint, "Registration should still be active");
    }
} 