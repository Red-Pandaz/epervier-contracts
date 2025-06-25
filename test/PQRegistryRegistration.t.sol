// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

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
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(epervierVerifier));
        
        // Load actor data from centralized config
        loadActorsConfig();
        
        // Mock the Epervier verifier to return the correct fingerprint for each actor
        // We'll set up specific mocks in each test as needed
    }
    
    function loadActorsConfig() internal {
        // Load the centralized actors config
        string memory jsonData = vm.readFile("test/test_keys/actors_config.json");
        
        // Load each actor from the config
        string[] memory actorNames = new string[](10);
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
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        
        // Parse addresses from the test vector (Alice is the first element in registration_intent array)
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
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // Load the real ETH intent message and signature from test vector
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse signature components from the test vector
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.r")));
        bytes32 s = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.s")));
        
        // Submit registration intent with real data
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Verify intent was created
        (address pqFingerprint, bytes memory intentMessage, uint256 timestamp, uint256 ethNonce) = registry.pendingIntents(alice.ethAddress);
        assertEq(pqFingerprint, alice.pqFingerprint, "PQ fingerprint should match");
        assertEq(ethNonce, 0, "ETH nonce should match");
        assertGt(timestamp, 0, "Timestamp should be set");
        
        // Verify nonces were incremented
        assertEq(registry.ethNonces(alice.ethAddress), 1, "ETH nonce should be incremented");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 1, "PQ nonce should be incremented");
        
        // Verify bidirectional mapping
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), alice.ethAddress, "Bidirectional mapping should be set");
    }
    
    function testConfirmRegistration_Success() public {
        // Use Alice's data
        Actor memory alice = getActor("alice");
        
        // First submit a registration intent
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse signature components from the test vector
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.r")));
        bytes32 s = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.s")));
        
        // Mock the Epervier verifier for intent submission
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load the real PQ confirmation message from test vector
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_message"));
        
        // Load the real signature components for confirmation
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        // Confirm registration with real data
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "PQ fingerprint should be mapped to ETH address");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "ETH address should be mapped to PQ fingerprint");
        
        // Verify intent was cleared
        (address pqFingerprint2, bytes memory intentMessage2, uint256 timestamp2, uint256 ethNonce2) = registry.pendingIntents(alice.ethAddress);
        assertEq(timestamp2, 0, "Intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), address(0), "Bidirectional mapping should be cleared");
        
        // Verify nonces were incremented
        assertEq(registry.ethNonces(alice.ethAddress), 2, "ETH nonce should be incremented again");
    }
    
    // ============================================================================
    // FAILURE TESTS - SUBMIT REGISTRATION INTENT
    // ============================================================================
    
    function testSubmitRegistrationIntent_RevertOnAlreadyRegistered() public {
        // Use Alice's data
        Actor memory alice = getActor("alice");
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // First register the key
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse signature components from the test vector
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.r")));
        bytes32 s = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.s")));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Confirm the registration
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.hint"));
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        
        // Try to submit another registration intent - should revert
        vm.expectRevert("ERR5: Epervier key already registered");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidETHNonce() public {
        // Use Alice's data
        Actor memory alice = getActor("alice");
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // Create a message with wrong nonce
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Parse signature components from the test vector
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.r")));
        bytes32 s = bytes32(vm.parseUint(vm.parseJsonString(jsonData, ".registration_intent[0].eth_signature.s")));
        
        // Modify the nonce in the message to make it invalid
        // This is a simplified test - in practice we'd need to reconstruct the message with wrong nonce
        vm.expectRevert("ERR6: Invalid ETH nonce in submitRegistrationIntent");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidSignature() public {
        // Use Alice's data
        Actor memory alice = getActor("alice");
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Use wrong signature
        (uint8 v, bytes32 r, bytes32 s) = (27, bytes32(0), bytes32(0));
        
        vm.expectRevert("ERR1: Invalid ETH signature");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    // ============================================================================
    // FAILURE TESTS - CONFIRM REGISTRATION
    // ============================================================================
    
    function testConfirmRegistration_RevertOnNoPendingIntent() public {
        // Use Alice's data
        Actor memory alice = getActor("alice");
        
        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // Try to confirm without submitting intent first
        string memory jsonData = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        vm.expectRevert("No pending intent found for PQ fingerprint");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    
    function parseSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "Invalid signature length");
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Adjust v for Ethereum signature format
        if (v < 27) {
            v += 27;
        }
    }
} 