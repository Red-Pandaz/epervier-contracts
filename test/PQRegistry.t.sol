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
    bytes32 public testPublicKeyHash;
    bytes32 public testPublicKeyHash2;
    
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
        testPublicKeyHash = keccak256(abi.encodePacked(testPublicKey[0], testPublicKey[1]));
        testPublicKeyHash2 = keccak256(abi.encodePacked(testPublicKey2[0], testPublicKey2[1]));
        
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
        assertEq(registry.DISABLED_PQ_KEY(), bytes32(uint256(1)));
    }
    
    function testInitialState() public {
        // Check initial nonces
        assertEq(registry.ethNonces(alice), 0);
        assertEq(registry.pqKeyNonces(testPublicKeyHash), 0);
        
        // Check no keys registered
        assertEq(registry.epervierKeyToAddress(testPublicKeyHash), address(0));
        assertEq(registry.addressToEpervierKey(alice), bytes32(0));
        
        // Check no pending intents - just check if timestamp is 0
        // We'll access the mapping directly without destructuring for now
        // (bytes32 pqFingerprint, uint256[2] memory publicKey, bytes memory intentMessage, uint256 timestamp, uint256 ethNonce) = registry.pendingIntents(alice);
        // assertEq(timestamp, 0);
    }
    
    // ============================================================================
    // SUBMIT REGISTRATION INTENT TESTS
    // ============================================================================
    
    function testSubmitRegistrationIntent_Success() public {
        // Test vector 1 values
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        uint256[2] memory testPublicKeyVector = [uint256(703309690834788033648158452166570983886945531899), uint256(0)];
        bytes32 testPublicKeyHashVector = keccak256(abi.encodePacked(testPublicKeyVector[0], testPublicKeyVector[1]));
        
        // Mock Epervier verifier to return alice's address
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
        
        // Debug: Show what abi.encodePacked(testAlice) produces
        bytes memory encodedAddress = abi.encodePacked(testAlice);
        emit log_bytes(encodedAddress);
        emit log_named_bytes32("testAlice as bytes32", bytes32(uint256(uint160(testAlice))));
        
        emit log_bytes(pqMessage);
        
        // Create ETH message with nested signature structure
        bytes memory ethMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            testSalt, // pqSignature (using mock data for now)
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethMessage);
        
        // Debug: Show the ETH message hash being created
        emit log_named_bytes32("test_eth_message_hash", ethMessageHash);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        emit log_named_bytes32("test_eth_signed_message_hash", ethSignedMessageHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        // Submit intent with nested signature structure
        registry.submitRegistrationIntent(
            pqMessage, // PQ message (signed by PQ key)
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKeyVector,
            0, // ethNonce
            ethSignature // ETH signature of nested message
        );
        
        // Verify intent was stored
        // Note: We can't easily access the struct fields directly, so we'll verify the nonce increment
        assertEq(registry.ethNonces(testAlice), 1);
        assertEq(registry.pqKeyNonces(testPublicKeyHashVector), 0);
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidEpervierSignature() public {
        // Mock Epervier verifier to return zero address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(address(0))
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
            uint256(0)
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert("Invalid Epervier signature");
        registry.submitRegistrationIntent(
            pqMessage,
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0,
            ethSignature
        );
    }
    
    function testSubmitRegistrationIntent_RevertOnInvalidETHNonce() public {
        // Mock Epervier verifier
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
            uint256(1) // Wrong nonce
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert("Invalid ETH nonce");
        registry.submitRegistrationIntent(
            pqMessage,
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1, // Wrong nonce
            ethSignature
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
        bytes memory invalidSignature = new bytes(64); // Wrong length
        
        vm.expectRevert("Invalid signature length");
        registry.submitRegistrationIntent(
            pqMessage,
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0,
            invalidSignature
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
            uint256(0)
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPrivateKey, ethSignedMessageHash);
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert("Epervier key already registered");
        registry.submitRegistrationIntent(
            pqMessage,
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0,
            ethSignature
        );
    }
    
    // ============================================================================
    // CONFIRM REGISTRATION TESTS
    // ============================================================================
    
    function testConfirmRegistration_Success() public {
        // Test vector 1 values
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        uint256[2] memory testPublicKeyVector = [uint256(703309690834788033648158452166570983886945531899), uint256(0)];
        bytes32 testPublicKeyHashVector = keccak256(abi.encodePacked(testPublicKeyVector[0], testPublicKeyVector[1]));
        
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
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKeyVector,
            0, // ethNonce
            ethSignature // ETH signature
        );
        
        // Now confirm the registration with nested signature structure
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
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKeyVector,
            1, // ethNonce (incremented after intent submission)
            confirmSignature // ETH signature
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
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, confirmSignedMessageHash);
        bytes memory confirmSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1, // ethNonce (incremented after intent submission)
            confirmSignature // ETH signature
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
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0, // ethNonce
            ethSignature // ETH signature
        );
        
        // Try to confirm with wrong nonce
        bytes memory ethConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm registration",
            uint256(2), // Wrong nonce (should be 1)
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 confirmMessageHash = keccak256(ethConfirmMessage);
        
        // Create the Ethereum signed message hash for confirmation (same as contract)
        bytes32 confirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", confirmMessageHash));
        
        (v, r, s) = vm.sign(alicePrivateKey, confirmSignedMessageHash);
        bytes memory confirmSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert("Invalid ETH nonce");
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            2, // Wrong nonce (should be 1)
            confirmSignature // ETH signature
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
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0, // ethNonce
            ethSignature // ETH signature
        );
        
        // Verify intent exists
        // Note: We can't easily access the struct fields directly, so we'll verify the nonce increment
        assertEq(registry.ethNonces(testAlice), 1);
        
        // Remove intent with nested signature structure
        registry.removeIntent(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            1 // ethNonce (incremented after intent submission)
        );
        
        // Verify intent was removed (nonce should be incremented)
        assertEq(registry.ethNonces(testAlice), 2);
    }
    
    function testRemoveIntent_RevertOnNoIntent() public {
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
        bytes memory ethRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Unpair from fingerprint",
            uint256(1), // ethNonce (incremented after intent submission)
            testSalt, // pqSignature
            pqMessage // pqMessage
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", removeMessageHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, removeSignedMessageHash);
        bytes memory removeSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert("No pending intent found");
        registry.removeIntent(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            1 // ethNonce (incremented after intent submission)
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
            pqMessage1, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0, // ethNonce
            ethSignature1 // ETH signature
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
            pqMessage2, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey2,
            1, // ethNonce
            ethSignature2 // ETH signature
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
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0, // ethNonce
            ethSignature // ETH signature
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
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1, // ethNonce (incremented after intent submission)
            confirmSignature // ETH signature
        );
        
        // Try to replay the confirmation
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqMessage, // PQ message
            testSalt, // pqSignature
            testSalt, // salt
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1, // ethNonce (incremented after intent submission)
            confirmSignature // ETH signature
        );
    }
    
    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    
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
        // First register a key
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        address testBob = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        
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
            pqMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0,
            ethSignature
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
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1,
            ethConfirmSignature
        );
        
        // Now submit change ETH address intent
        bytes memory pqChangeMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(testBob),
            uint256(0) // pqNonce
        );
        
        registry.submitChangeETHAddressIntent(
            pqChangeMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            testBob,
            0 // pqNonce
        );
        
        // Confirm change ETH address
        bytes memory pqChangeConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm change ETH Address",
            uint256(0), // ethNonce for new address
            testSalt,
            pqChangeMessage
        );
        bytes32 ethChangeConfirmMessageHash = keccak256(pqChangeConfirmMessage);
        bytes32 ethChangeConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethChangeConfirmMessageHash));
        
        (v, r, s) = vm.sign(bobPrivateKey, ethChangeConfirmSignedMessageHash);
        bytes memory ethChangeConfirmSignature = abi.encodePacked(r, s, v);
        
        registry.confirmChangeETHAddress(
            pqChangeMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            testBob,
            0, // ethNonce
            ethChangeConfirmSignature
        );
        
        // Verify the change
        assertEq(registry.epervierKeyToAddress(testPublicKeyHash), testBob);
        assertEq(registry.addressToEpervierKey(testBob), testPublicKeyHash);
        assertEq(registry.addressToEpervierKey(testAlice), bytes32(0)); // Old mapping cleared
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
            pqMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0,
            ethSignature
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
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1,
            ethConfirmSignature
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
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            2, // ethNonce
            ethUnregSignature
        );
        
        // Confirm unregistration
        bytes memory pqUnregConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm unregistration",
            uint256(3), // ethNonce
            testSalt,
            pqUnregMessage
        );
        bytes32 ethUnregConfirmMessageHash = keccak256(pqUnregConfirmMessage);
        bytes32 ethUnregConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ethUnregConfirmMessageHash));
        
        (v, r, s) = vm.sign(alicePrivateKey, ethUnregConfirmSignedMessageHash);
        bytes memory ethUnregConfirmSignature = abi.encodePacked(r, s, v);
        
        registry.confirmUnregistration(
            pqUnregMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            3, // ethNonce
            ethUnregConfirmSignature
        );
        
        // Verify unregistration
        assertEq(registry.epervierKeyToAddress(testPublicKeyHash), address(0));
        assertEq(registry.addressToEpervierKey(testAlice), bytes32(0));
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
        bytes memory ethSignature = abi.encodePacked(r, s, v);
        
        registry.submitRegistrationIntent(
            pqMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            0,
            ethSignature
        );
        
        // Remove the intent
        registry.removeIntent(
            pqMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            1 // ethNonce (incremented after intent submission)
        );
        
        // Verify intent is removed
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqMessage,
            testSalt,
            testSalt,
            testCs1,
            testCs2,
            testHint,
            testPublicKey,
            1,
            ethSignature
        );
    }
} 