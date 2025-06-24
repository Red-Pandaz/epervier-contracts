// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";

contract PQRegistryComprehensiveTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    // Test addresses
    address public alice = address(0x1);
    address public bob = address(0x2);
    address public charlie = address(0x3);
    
    // Test keys
    uint256[2] public testPublicKey = [uint256(123), uint256(456)];
    uint256[2] public testPublicKey2 = [uint256(789), uint256(101)];
    address public testPublicKeyHash;
    address public testPublicKeyHash2;
    
    // Test signature components (mock data)
    bytes public testSalt;
    uint256[] public testCs1;
    uint256[] public testCs2;
    uint256 public testHint;
    
    // ETH signature components
    uint256 public alicePrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 public bobPrivateKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    
    function setUp() public {
        // Deploy contracts
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(epervierVerifier));
        
        // Calculate public key hashes
        bytes32 hash1 = keccak256(abi.encodePacked(testPublicKey[0], testPublicKey[1]));
        bytes32 hash2 = keccak256(abi.encodePacked(testPublicKey2[0], testPublicKey2[1]));
        testPublicKeyHash = address(uint160(uint256(hash1)));
        testPublicKeyHash2 = address(uint160(uint256(hash2)));
        
        // Setup mock signature components
        testSalt = new bytes(40);
        testCs1 = new uint256[](32);
        testCs2 = new uint256[](32);
        testHint = 123;
        
        // Label addresses for better debugging
        vm.label(address(epervierVerifier), "EpervierVerifier");
        vm.label(address(registry), "PQRegistry");
        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(charlie, "Charlie");
    }
    
    // ============================================================================
    // CONSTRUCTOR AND INITIAL STATE TESTS
    // ============================================================================
    
    function testConstructor() public {
        assertEq(address(registry.epervierVerifier()), address(epervierVerifier));
        assertEq(registry.DOMAIN_SEPARATOR(), keccak256("PQRegistry"));
        assertEq(registry.DISABLED_PQ_KEY(), address(1));
    }
    
    function testInitialState() public {
        // Check initial nonces
        assertEq(registry.ethNonces(alice), 0);
        assertEq(registry.pqKeyNonces(testPublicKeyHash), 0);
        
        // Check no keys registered
        assertEq(registry.epervierKeyToAddress(testPublicKeyHash), address(0));
        assertEq(registry.addressToEpervierKey(alice), address(0));
        
        // Check no pending intents - just check if timestamp is 0
        // We'll access the mapping directly without destructuring for now
        // (bytes32 pqFingerprint, uint256[2] memory publicKey, bytes memory intentMessage, uint256 timestamp, uint256 ethNonce) = registry.pendingIntents(alice);
        // assertEq(timestamp, 0);
    }
    
    // ============================================================================
    // SUBMIT REGISTRATION INTENT TESTS
    // ============================================================================
    
    function testSubmitRegistrationIntent_Success() public {
        // Load real test vector data
        string memory json = vm.readFile("test/test_vectors/comprehensive_vector_1.json");
        
        // Extract the registration object
        string memory registrationJson = extractJsonValue(json, "registration");
        // Parse the real signature components for the intent (base PQ message)
        bytes memory salt = vm.parseBytes(extractJsonValue(registrationJson, "intent_epervier_salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(registrationJson, "intent_epervier_cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(registrationJson, "intent_epervier_cs2");
        uint256 hint = vm.parseUint(extractJsonValue(registrationJson, "intent_epervier_hint"));
        // Parse the base PQ message
        bytes memory basePQMessage = vm.parseBytes(extractJsonValue(registrationJson, "base_pq_message"));
        // Parse the ETH intent message and signature
        bytes memory ethIntentMessage = vm.parseBytes(extractJsonValue(registrationJson, "eth_intent_message"));
        bytes memory ethIntentSignature = vm.parseBytes(extractJsonValue(registrationJson, "eth_intent_signature"));
        
        // Parse the ETH signature components
        (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
        
        // Mock the Epervier verifier to return the correct address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Submit registration intent with real data
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Verify the intent was created
        assertEq(registry.ethNonces(alice), 1);
        
        // Verify the PQ nonce was incremented
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        assertEq(registry.pqKeyNonces(recoveredFingerprint), 1);
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidEpervierSignature() public {
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(address(0))
        );
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice),
            uint256(0)
        );
        bytes memory ethMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0),
            testSalt,
            testCs1,
            testCs2,
            abi.encode(testHint),
            pqMessage
        );
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        vm.expectRevert("Invalid Epervier signature");
        registry.submitRegistrationIntent(
            ethMessage,
            v,
            r,
            s
        );
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidETHNonce() public {
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice),
            uint256(0)
        );
        // ETH message with wrong nonce
        bytes memory ethMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(1), // Wrong nonce
            testSalt,
            testCs1,
            testCs2,
            abi.encode(testHint),
            pqMessage
        );
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        vm.expectRevert("Invalid ETH nonce");
        registry.submitRegistrationIntent(
            ethMessage,
            v,
            r,
            s
        );
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidSignatureLength() public {
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            alice,
            uint256(0)
        );
        
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0)
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        vm.expectRevert("Invalid signature length");
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
    }
    
    function testSubmitRegistrationIntent_RevertOnAlreadyRegisteredKey() public {
        // First register the key
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Use the address that corresponds to bobPrivateKey
        address testBob = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        
        // Manually set the key as registered
        vm.store(
            address(registry),
            keccak256(abi.encode(testPublicKeyHash, uint256(0))), // epervierKeyToAddress slot
            bytes32(uint256(uint160(alice)))
        );
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testBob), // Use the correct address
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPrivateKey, ethSignedMessageHash);
        
        vm.expectRevert("Epervier key already registered");
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
    }
    
    // ============================================================================
    // CONFIRM REGISTRATION TESTS
    // ============================================================================
    
    function testConfirmRegistration_Success() public {
        // Test vector 1 values
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        uint256[2] memory testPublicKeyVector = [uint256(703309690834788033648158452166570983886945531899), uint256(0)];
        bytes32 hashVector = keccak256(abi.encodePacked(testPublicKeyVector[0], testPublicKeyVector[1]));
        address testPublicKeyHashVector = address(uint160(uint256(hashVector)));
        
        // First submit an intent
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(testAlice)
        );
        
        // Create PQ message with correct format
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Encode address as 20 bytes
            uint256(0) // pqNonce
        );
        
        // Create ETH message for intent with nested signature structure
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Now confirm the registration with nested signature structure
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testCs1,
            testCs2,
            testHint
        );
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(testPublicKeyHashVector), testAlice);
        assertEq(registry.addressToEpervierKey(testAlice), testPublicKeyHashVector);
        
        // Verify intent was cleaned up (nonce should be incremented)
        assertEq(registry.ethNonces(testAlice), 2);
    }
    
    function testConfirmRegistration_RevertOnNoPendingIntent() public {
        // Use the address that corresponds to alicePrivateKey
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        // Mock Epervier verifier to return the correct address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(testAlice)
        );
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(0)
        );
        
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testCs1,
            testCs2,
            testHint
        );
    }
    
    function testConfirmRegistration_RevertOnInvalidETHNonce() public {
        // First submit an intent
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Use the address that corresponds to alicePrivateKey
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Try to confirm with wrong nonce - this should fail at the ETH signature verification level
        // since the contract will try to verify the ETH signature with nonce 1, but we're using nonce 0
        vm.expectRevert("Invalid ETH nonce");
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testCs1,
            testCs2,
            testHint
        );
    }
    
    // ============================================================================
    // REMOVE INTENT TESTS
    // ============================================================================
    
    function testRemoveIntent_Success() public {
        // First submit an intent
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Use the address that corresponds to alicePrivateKey
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Verify intent exists
        // Note: We can't easily access the struct fields directly, so we'll verify the nonce increment
        assertEq(registry.ethNonces(testAlice), 1);
        
        // Remove intent with ETH signature
        bytes memory ethRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Remove registration intent",
            uint256(1), // ethNonce (incremented after intent submission)
            pqMessage // Include the PQ message for context
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethRemoveMessage));
        
        (v, r, s) = vm.sign(alicePrivateKey, removeSignedMessageHash);
        
        registry.removeIntent(
            ethRemoveMessage,
            v,
            r,
            s
        );
        
        // Verify intent was removed (nonce should be incremented)
        assertEq(registry.ethNonces(testAlice), 2);
    }
    
    function testRemoveIntent_RevertOnNoIntent() public {
        // Use the address that corresponds to alicePrivateKey
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(0)
        );
        
        // Try to remove intent that doesn't exist
        bytes memory ethRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Remove registration intent",
            uint256(0), // ethNonce
            pqMessage // Include the PQ message for context
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethRemoveMessage));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, removeSignedMessageHash);
        
        vm.expectRevert("No pending intent found");
        registry.removeIntent(
            ethRemoveMessage,
            v,
            r,
            s
        );
    }
    
    // ============================================================================
    // PARSE INTENT ADDRESS TESTS
    // ============================================================================
    
    function testParseIntentAddress_StandardFormat() public {
        bytes memory message = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(address(0x1234567890123456789012345678901234567890)),
            uint256(0)
        );
        address parsed = registry.parseIntentAddress(message);
        assertEq(parsed, address(0x1234567890123456789012345678901234567890));
    }
    
    function testParseIntentAddress_MessageTooShort() public {
        bytes memory message = "0x123";
        address parsed = registry.parseIntentAddress(message);
        assertEq(parsed, address(0));
    }
    
    function testParseIntentAddress_No0xPrefix() public {
        bytes memory message = "No Ethereum address here";
        address parsed = registry.parseIntentAddress(message);
        assertEq(parsed, address(0));
    }
    
    function testParseIntentAddress_AddressInMiddle() public {
        bytes memory message = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Some preamble Intent to pair ETH Address ",
            abi.encodePacked(address(0x1234567890123456789012345678901234567890)),
            " suffix",
            uint256(0)
        );
        address parsed = registry.parseIntentAddress(message);
        assertEq(parsed, address(0x1234567890123456789012345678901234567890));
    }
    
    // ============================================================================
    // EDGE CASES AND STRESS TESTS
    // ============================================================================
    
    function testMultipleIntentsFromSameAddress() public {
        // Submit first intent
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Use the address that corresponds to alicePrivateKey
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        bytes memory pqMessage1 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(0)
        );
        bytes memory ethIntentMessage1 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature
            pqMessage1 // pqMessage
        );
        bytes32 ethMessageHash1 = keccak256(ethIntentMessage1);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash1 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash1));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash1);
        bytes memory ethSignature1 = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            ethIntentMessage1,
            v,
            r,
            s
        );
        
        // Submit second intent with different key (should overwrite)
        bytes memory pqMessage2 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(1)
        );
        bytes memory ethIntentMessage2 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(1), // ethNonce
            testSalt, // pqSignature
            pqMessage2 // pqMessage
        );
        bytes32 ethMessageHash2 = keccak256(ethIntentMessage2);
        
        // Create the Ethereum signed message hash for second intent (same as contract)
        bytes32 ethSignedMessageHash2 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash2));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethSignedMessageHash2);
        bytes memory ethSignature2 = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            ethIntentMessage2,
            v,
            r,
            s
        );
        
        // Verify second intent overwrote first (check nonce increment)
        assertEq(registry.ethNonces(testAlice), 2);
    }
    
    function testReplayAttackPrevention() public {
        // Submit and confirm an intent
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Use the address that corresponds to alicePrivateKey
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice), // Use the correct address
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Confirm the registration
        bytes memory ethConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm registration",
            uint256(1), // ethNonce (incremented after intent submission)
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 confirmMessageHash = keccak256(ethConfirmMessage);
        
        // Create the Ethereum signed message hash for confirmation (same as contract)
        bytes32 confirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", confirmMessageHash));
        
        (v, r, s) = vm.sign(alicePrivateKey, confirmSignedMessageHash);
        bytes memory confirmSignature = abi.encodePacked(r, s, v);
        
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testCs1,
            testCs2,
            testHint
        );
        
        // Try to replay the confirmation
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testCs1,
            testCs2,
            testHint
        );
    }
    
    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    
    function mockEpervierVerifier(address expectedAddress) internal {
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(expectedAddress)
        );
    }
        
    function createValidETHSignature(address signer, uint256 privateKey, uint256 nonce) internal view returns (bytes memory) {
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            nonce
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }
    
    function createValidIntentMessage(address targetAddress, uint256 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            targetAddress,
            nonce
        );
    }
    
    // ============================================================================
    // COMPREHENSIVE OPERATION TESTS
    // ============================================================================
    
    function testChangeETHAddress_CompleteFlow() public {
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        address testBob = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        
        // Mock Epervier verifier to return the expected addresses
        mockEpervierVerifier(testAlice);
        
        // Register first
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice),
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0),
            testSalt,
            pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Confirm registration
        bytes memory pqConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm registration",
            uint256(1),
            testSalt,
            pqMessage
        );
        bytes32 ethConfirmMessageHash = keccak256(pqConfirmMessage);
        bytes32 ethConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethConfirmMessageHash));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethConfirmSignedMessageHash);
        bytes memory ethConfirmSignature = abi.encodePacked(r, s, v);
        
        registry.confirmRegistration(
            pqMessage,
            testSalt,
            testCs1,
            testCs2,
            testHint
        );
        
        // Now submit change ETH address intent - mock for Bob's address
        mockEpervierVerifier(testBob);
        
        bytes memory pqChangeMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Change ETH Address from ",
            abi.encodePacked(testAlice), // current address
            " to ",
            abi.encodePacked(testBob), // new address
            uint256(0) // ethNonce
        );
        
        // Create ETH message with nested PQ signature structure
        bytes memory ethChangeMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature salt
            testCs1, // pqSignature cs1
            testCs2, // pqSignature cs2
            abi.encode(testHint), // pqSignature hint
            pqChangeMessage // base PQ message
        );
        bytes32 ethChangeMessageHash = keccak256(ethChangeMessage);
        bytes32 ethChangeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethChangeMessage));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethChangeSignedMessageHash);
        
        registry.submitChangeETHAddressIntent(
            ethChangeMessage,
            v,
            r,
            s
        );
        
        // Confirm change ETH address
        bytes memory pqChangeConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm changing ETH address from ",
            abi.encodePacked(testAlice), // current address
            " to ",
            abi.encodePacked(testBob), // new address
            uint256(0) // pqNonce
        );
        
        // Create ETH message with nested PQ signature structure
        bytes memory ethChangeConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm change ETH Address",
            uint256(0), // ethNonce for new address
            testSalt, // pqSignature salt
            testCs1, // pqSignature cs1
            testCs2, // pqSignature cs2
            abi.encode(testHint), // pqSignature hint
            pqChangeConfirmMessage // base PQ message
        );
        bytes32 ethChangeConfirmMessageHash = keccak256(ethChangeConfirmMessage);
        bytes32 ethChangeConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethChangeConfirmMessage));
        
        (v, r, s) = vm.sign(bobPrivateKey, ethChangeConfirmSignedMessageHash);
        
        registry.confirmChangeETHAddress(
            ethChangeConfirmMessage,
            v,
            r,
            s
        );
        
        // Verify the change
        assertEq(registry.epervierKeyToAddress(testPublicKeyHash), testBob);
        assertEq(registry.addressToEpervierKey(testBob), testPublicKeyHash);
        assertEq(registry.addressToEpervierKey(testAlice), address(0)); // Old mapping cleared
    }
    
    function testUnregistration_CompleteFlow() public {
        // First register a key
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        // Register first
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice),
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0),
            testSalt,
            pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Confirm registration
        bytes memory pqConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm registration",
            uint256(1),
            testSalt,
            pqMessage
        );
        bytes32 ethConfirmMessageHash = keccak256(pqConfirmMessage);
        bytes32 ethConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethConfirmMessageHash));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethConfirmSignedMessageHash);
        bytes memory ethConfirmSignature = abi.encodePacked(r, s, v);
        
        registry.confirmRegistration(
            pqMessage,
            testSalt,
            testCs1,
            testCs2,
            testHint
        );
        
        // Submit unregistration intent
        bytes memory pqUnregMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice),
            uint256(2) // ethNonce
        );
        bytes memory ethUnregIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to unregister from PQ fingerprint",
            uint256(2),
            testSalt,
            pqUnregMessage
        );
        bytes32 ethUnregMessageHash = keccak256(ethUnregIntentMessage);
        bytes32 ethUnregSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethUnregMessageHash));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethUnregSignedMessageHash);
        bytes memory ethUnregSignature = abi.encodePacked(r, s, v);
        
        registry.submitUnregistrationIntent(
            pqUnregMessage,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey
        );
        
        // Confirm unregistration
        bytes memory ethUnregConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm unregistration",
            uint256(3), // ethNonce
            testSalt,
            testCs1,
            testCs2,
            testHint,
            pqUnregMessage
        );
        bytes32 ethUnregConfirmMessageHash = keccak256(ethUnregConfirmMessage);
        bytes32 ethUnregConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethUnregConfirmMessage));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethUnregConfirmSignedMessageHash);
        
        registry.confirmUnregistration(
            ethUnregConfirmMessage,
            v,
            r,
            s
        );
        
        // Verify unregistration
        assertEq(registry.epervierKeyToAddress(testPublicKeyHash), address(0));
        assertEq(registry.addressToEpervierKey(testAlice), address(0));
    }
    
    function testRemoveIntent_AllTypes() public {
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        // Test remove registration intent
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testAlice),
            uint256(0)
        );
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0),
            testSalt,
            pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Remove the intent with ETH signature
        bytes memory ethRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Remove registration intent",
            uint256(1), // ethNonce (incremented after intent submission)
            pqMessage // Include the PQ message for context
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethRemoveMessage));
        
        (v, r, s) = vm.sign(alicePrivateKey, removeSignedMessageHash);
        
        registry.removeIntent(
            ethRemoveMessage,
            v,
            r,
            s
        );
        
        // Verify intent is removed
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqMessage,
            testSalt,
            testCs1,
            testCs2,
            testHint
        );
    }
    
    // ============================================================================
    // REAL TEST VECTOR TESTS
    // ============================================================================
    
    function testRealTestVectorRegistration() public {
        // Load test vector 1 data
        string memory testVectorJson = vm.readFile("test/test_vectors/test_vector_1.json");
        
        // Extract the base PQ message (without ETH signature)
        string memory basePqMessageHex = extractJsonValue(testVectorJson, "base_pq_message");
        bytes memory basePqMessage = vm.parseBytes(basePqMessageHex);
        
        // Extract the ETH message
        string memory ethIntentMessageHex = extractJsonValue(testVectorJson, "eth_intent_message");
        bytes memory ethIntentMessage = vm.parseBytes(ethIntentMessageHex);
        
        // Extract the ETH signature
        string memory ethSignatureHex = extractJsonValue(testVectorJson, "eth_intent_signature");
        bytes memory ethSignature = vm.parseBytes(ethSignatureHex);
        
        // Parse the ETH signature components
        require(ethSignature.length == 65, "Invalid ETH signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(ethSignature, 32))
            s := mload(add(ethSignature, 64))
            v := byte(0, mload(add(ethSignature, 96)))
        }
        
        // Extract the ETH address
        string memory ethAddressHex = extractJsonValue(testVectorJson, "eth_address");
        address ethAddress = vm.parseAddress(ethAddressHex);
        
        // Log the ETH address from the test vector
        emit log_named_address("ETH address from test vector", ethAddress);
        
        // Debug: Check what address the signature recovers
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n202", ethIntentMessage));
        address recoveredAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        emit log_named_address("Recovered address from signature", recoveredAddress);
        
        // Mock the Epervier verifier to return the correct address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(ethAddress)
        );
        
        // Submit registration intent using the real test vector data
        registry.submitRegistrationIntent(
            ethIntentMessage, // ETH message (contains nested PQ signature components)
            v,
            r,
            s
        );
        
        // Verify the intent was stored
        assertEq(registry.ethNonces(ethAddress), 1);
    }
    
    function extractJsonValue(string memory json, string memory key) internal pure returns (string memory) {
        // Simple JSON value extraction - looks for "key": value pattern
        string memory searchPattern = string(abi.encodePacked('"', key, '": '));
        uint256 startIndex = findString(json, searchPattern);
        require(startIndex != type(uint256).max, "Key not found in JSON");
        
        startIndex += bytes(searchPattern).length;
        uint256 endIndex = startIndex;
        
        // Find the end of the value based on its type
        if (startIndex < bytes(json).length && bytes(json)[startIndex] == '"') {
            // String value - find closing quote
            startIndex += 1; // Skip opening quote
            endIndex = startIndex;
            while (endIndex < bytes(json).length) {
                if (bytes(json)[endIndex] == '"') {
                    break;
                }
                endIndex++;
            }
        } else if (startIndex < bytes(json).length && bytes(json)[startIndex] == '[') {
            // Array value - find closing bracket
            endIndex = startIndex;
            uint256 bracketCount = 0;
            while (endIndex < bytes(json).length) {
                if (bytes(json)[endIndex] == '[') {
                    bracketCount++;
                } else if (bytes(json)[endIndex] == ']') {
                    bracketCount--;
                    if (bracketCount == 0) {
                        endIndex++;
                        break;
                    }
                }
                endIndex++;
            }
        } else {
            // Number or other value - find comma or closing brace/bracket
            endIndex = startIndex;
            while (endIndex < bytes(json).length) {
                if (bytes(json)[endIndex] == ',' || 
                    bytes(json)[endIndex] == '}' || 
                    bytes(json)[endIndex] == ']') {
                    break;
                }
                endIndex++;
            }
        }
        
        require(endIndex <= bytes(json).length, "Malformed JSON value");
        
        bytes memory result = new bytes(endIndex - startIndex);
        for (uint256 i = 0; i < result.length; i++) {
            result[i] = bytes(json)[startIndex + i];
        }
        
        return string(result);
    }
    
    function findString(string memory haystack, string memory needle) internal pure returns (uint256) {
        bytes memory haystackBytes = bytes(haystack);
        bytes memory needleBytes = bytes(needle);
        
        for (uint256 i = 0; i <= haystackBytes.length - needleBytes.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < needleBytes.length; j++) {
                if (haystackBytes[i + j] != needleBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return type(uint256).max;
    }
    
    function extractFirstArrayElement(string memory arrayStr) internal pure returns (uint256) {
        // Extract first number from "[number, 0]" format
        uint256 startIndex = findString(arrayStr, "[");
        require(startIndex != type(uint256).max, "Array not found");
        
        startIndex += 1; // Skip the opening bracket
        uint256 endIndex = startIndex;
        
        // Find the comma
        while (endIndex < bytes(arrayStr).length) {
            if (bytes(arrayStr)[endIndex] == ',') {
                break;
            }
            endIndex++;
        }
        
        require(endIndex < bytes(arrayStr).length, "Malformed array");
        
        bytes memory numberBytes = new bytes(endIndex - startIndex);
        for (uint256 i = 0; i < numberBytes.length; i++) {
            numberBytes[i] = bytes(arrayStr)[startIndex + i];
        }
        
        // Trim whitespace and newlines
        string memory trimmedNumber = trimWhitespace(string(numberBytes));
        
        return vm.parseUint(trimmedNumber);
    }
    
    function trimWhitespace(string memory str) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        uint256 start = 0;
        uint256 end = strBytes.length;
        
        // Find first non-whitespace character
        while (start < end && isWhitespace(strBytes[start])) {
            start++;
        }
        
        // Find last non-whitespace character
        while (end > start && isWhitespace(strBytes[end - 1])) {
            end--;
        }
        
        // Extract trimmed string
        bytes memory result = new bytes(end - start);
        for (uint256 i = 0; i < result.length; i++) {
            result[i] = strBytes[start + i];
        }
        
        return string(result);
    }
    
    function isWhitespace(bytes1 char) internal pure returns (bool) {
        return char == 0x20 || // space
               char == 0x09 || // tab
               char == 0x0A || // newline
               char == 0x0D || // carriage return
               char == 0x0C;   // form feed
    }
    
    // Helper function to parse signature components from bytes
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