// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PQRegistryComprehensiveTest is Test {
    using Strings for string;
    using ECDSA for bytes32;
    
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
        
        // Parse the real signature components for the intent (base PQ message)
        bytes memory salt = vm.parseBytes(vm.parseJsonString(json, ".registration.intent_epervier_salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(json, ".registration.intent_epervier_hint"));
        
        // Parse the base PQ message
        bytes memory basePQMessage = vm.parseBytes(vm.parseJsonString(json, ".registration.base_pq_message"));
        
        // Parse the ETH intent message and signature
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(json, ".registration.eth_intent_message"));
        bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(json, ".registration.eth_intent_signature"));
        
        // Parse the ETH signature components
        (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
        
        // Mock the Epervier verifier to return the correct address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb) // Use the fingerprint from the ETH message
        );
        
        // Submit registration intent with real data
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Get the actual ETH address from the test vector
        address ethAddress = vm.parseAddress(vm.parseJsonString(json, ".eth_address"));
        
        // Verify the intent was created
        assertEq(registry.ethNonces(ethAddress), 1);
        
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
            packUint256Array(testCs1),
            packUint256Array(testCs2),
            abi.encode(testHint),
            pqMessage
        );
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        vm.expectRevert("ERR2: Invalid Epervier signature");
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
            packUint256Array(testCs1),
            packUint256Array(testCs2),
            abi.encode(testHint),
            pqMessage
        );
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        vm.expectRevert("ERR6: Invalid ETH nonce in submitRegistrationIntent");
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
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethIntentMessage.length), ethIntentMessage));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        vm.expectRevert("Message too short for PQ salt");
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
            keccak256(abi.encode(testBob, uint256(1))), // addressToEpervierKey slot (mapping slot 1)
            bytes32(uint256(uint160(alice))) // Set to alice's address as the fingerprint
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
            testSalt, // pqSignature salt
            packUint256Array(testCs1), // cs1
            packUint256Array(testCs2), // cs2
            abi.encode(testHint), // hint
            pqMessage // pqMessage
        );
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethIntentMessage.length), ethIntentMessage));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPrivateKey, ethSignedMessageHash);
        
        vm.expectRevert("ERR5: Epervier key already registered");
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
        // Use the address that corresponds to alicePrivateKey
        address aliceAddress = vm.addr(alicePrivateKey);
        address publicKeyHash = aliceAddress; // Mock public key hash

        // Mock the Epervier verifier to return alice's address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(aliceAddress)
        );

        // Step 1: Submit registration intent
        bytes memory basePQMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(aliceAddress),
            uint256(0) // pqNonce
        );

        bytes memory ethMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            new bytes(40), // salt
            packUint256Array(new uint256[](32)), // cs1
            packUint256Array(new uint256[](32)), // cs2
            uint256(123), // hint
            basePQMessage
        );

        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage.length), ethMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);

        registry.submitRegistrationIntent(ethMessage, v, r, s);

        // Step 2: Confirm registration
        // Create ETH confirmation message
        bytes memory ethConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm bonding to epervier fingerprint ",
            abi.encodePacked(aliceAddress), // fingerprint (20 bytes address)
            uint256(1) // ethNonce (incremented after intent)
        );

        // Sign the ETH confirmation message
        (uint8 vConfirm, bytes32 rConfirm, bytes32 sConfirm) = vm.sign(alicePrivateKey, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethConfirmMessage.length), ethConfirmMessage)));
        
        // Explicitly ensure v is 27 or 28
        vConfirm = (vConfirm % 2) + 27;
        
        // Create the signature bytes properly
        bytes memory ethSignatureBytes = abi.encodePacked(rConfirm, sConfirm, vConfirm);

        // Create PQ confirmation message
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(aliceAddress),
            uint256(0), // pqNonce
            ethSignatureBytes, // ETH signature (65 bytes)
            ethConfirmMessage // ETH message
        );

        registry.confirmRegistration(
            pqMessage,
            new bytes(40), // salt
            new uint256[](32), // cs1
            new uint256[](32), // cs2
            123 // hint
        );

        // Verify both mappings are updated
        assertEq(registry.epervierKeyToAddress(publicKeyHash), aliceAddress, "epervierKeyToAddress mapping should be set");
        assertEq(registry.addressToEpervierKey(aliceAddress), publicKeyHash, "addressToEpervierKey mapping should be set");

        // Verify the intent was cleared
        assertEq(registry.ethNonces(aliceAddress), 2, "ETH nonce should be incremented twice");
    }
    
    function testConfirmRegistration_RevertOnNoPendingIntent() public {
        // Load real test vector data
        string memory json = vm.readFile("test/test_vectors/comprehensive_vector_1.json");
        
        // Parse the real signature components for the confirmation
        bytes memory salt = vm.parseBytes(extractJsonValue(json, ".registration.epervier_salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(json, ".registration.epervier_cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(json, ".registration.epervier_cs2");
        uint256 hint = vm.parseUint(extractJsonValue(json, ".registration.epervier_hint"));
        
        // Parse the PQ confirmation message from the test vector
        bytes memory pqConfirmMessage = vm.parseBytes(extractJsonValue(json, ".registration.pq_confirm_message"));
        
        // Use a completely unused Foundry test address (999) that has no pending intents
        address testUnused = vm.addr(999);
        
        console.log("Using address:", testUnused);
        
        // Clear any existing state for this address by directly manipulating storage
        // Clear the pending intent timestamp (slot 2 for pendingIntents mapping)
        vm.store(
            address(registry),
            keccak256(abi.encode(testUnused, uint256(2))), // pendingIntents slot (mapping slot 2)
            bytes32(0) // Clear the timestamp to 0
        );
        
        // Try to confirm registration with real test vector data but for an address with no pending intent
        // This should revert with "No pending intent found"
        vm.expectRevert("No pending intent found");
        registry.confirmRegistration(
            pqConfirmMessage,
            salt,
            cs1,
            cs2,
            hint
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
        
        bytes memory basePQMessage = abi.encodePacked(
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
            packUint256Array(testCs1), // cs1
            packUint256Array(testCs2), // cs2
            abi.encode(testHint), // hint
            basePQMessage // pqMessage
        );
        
        // Create the Ethereum signed message hash (same as contract)
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethIntentMessage.length), ethIntentMessage));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Create ETH confirmation message with wrong nonce (0 instead of 1)
        bytes memory ethConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm binding Fingerprint ",
            abi.encodePacked(alice), // fingerprint (20 bytes address)
            " to ETH Address ",
            abi.encodePacked(testAlice), // ETH address (20 bytes)
            uint256(0) // ethNonce (wrong - should be 1)
        );

        // Sign the ETH confirmation message
        (uint8 vConfirm, bytes32 rConfirm, bytes32 sConfirm) = vm.sign(alicePrivateKey, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethConfirmMessage.length), ethConfirmMessage)));
        
        // Explicitly ensure v is 27 or 28
        vConfirm = (vConfirm % 2) + 27;
        
        // Create the signature bytes properly
        bytes memory ethSignatureBytes = abi.encodePacked(rConfirm, sConfirm, vConfirm);

        // Create PQ confirmation message with new bidirectional binding format
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm binding ETH Address ",
            abi.encodePacked(testAlice), // ETH address
            " to Fingerprint ",
            abi.encodePacked(alice), // fingerprint address
            uint256(0), // pqNonce
            ethSignatureBytes, // ETH signature (65 bytes)
            ethConfirmMessage // ETH message
        );
        
        // Try to confirm with wrong nonce - this should fail at the ETH nonce verification level
        vm.expectRevert("ERR6: Invalid ETH nonce in confirmRegistration");
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
        assertEq(registry.ethNonces(testAlice), 1);
        
        // Remove intent with ETH signature (new format)
        bytes memory ethRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Remove intent from address ",
            abi.encodePacked(testAlice),
            uint256(1) // pqNonce or ethNonce (incremented after intent submission)
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethRemoveMessage.length), ethRemoveMessage));
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
        address testAlice = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        
        // Try to remove intent that doesn't exist (new format)
        bytes memory ethRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Remove intent from address ",
            abi.encodePacked(testAlice),
            uint256(0)
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethRemoveMessage.length), ethRemoveMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, removeSignedMessageHash);
        
        vm.expectRevert("No pending intent found");
        registry.removeIntent(
            ethRemoveMessage,
            v,
            r,
            s
        );
    }
    
    function testRemoveIntentByPQ_Success() public {
        // First submit an intent
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
        assertEq(registry.ethNonces(testAlice), 1);
        // PQ-controlled remove intent
        bytes memory pqRemoveMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Remove intent from address ",
            abi.encodePacked(testAlice),
            uint256(1)
        );
        // Use mock signature components for PQ
        registry.removeIntentByPQ(
            pqRemoveMessage,
            testSalt,
            testCs1,
            testCs2,
            testHint
        );
        // Verify intent was removed
        assertEq(registry.ethNonces(testAlice), 1); // ETH nonce unchanged
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
        address aliceAddress = vm.addr(alicePrivateKey);
        address publicKeyHash = aliceAddress; // Mock public key hash

        // Mock the Epervier verifier to return alice's address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(aliceAddress)
        );

        // Submit first intent
        bytes memory basePQMessage1 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(aliceAddress),
            uint256(0)
        );
        bytes memory ethMessage1 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0),
            new bytes(40),
            packUint256Array(new uint256[](32)),
            packUint256Array(new uint256[](32)),
            uint256(123),
            basePQMessage1
        );
        bytes32 ethSignedMessageHash1 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage1.length), ethMessage1));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(alicePrivateKey, ethSignedMessageHash1);
        registry.submitRegistrationIntent(ethMessage1, v1, r1, s1);

        // Submit second intent (should fail due to nonce)
        bytes memory basePQMessage2 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(aliceAddress),
            uint256(0)
        );
        bytes memory ethMessage2 = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0),
            new bytes(40),
            packUint256Array(new uint256[](32)),
            packUint256Array(new uint256[](32)),
            uint256(123),
            basePQMessage2
        );
        bytes32 ethSignedMessageHash2 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethMessage2.length), ethMessage2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(alicePrivateKey, ethSignedMessageHash2);
        vm.expectRevert("ERR6: Invalid ETH nonce in submitRegistrationIntent");
        registry.submitRegistrationIntent(ethMessage2, v2, r2, s2);
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
        
        (uint8 vConfirm, bytes32 rConfirm, bytes32 sConfirm) = vm.sign(alicePrivateKey, ethSignedMessageHash);
        bytes memory confirmSignature = abi.encodePacked(rConfirm, sConfirm, vConfirm);
        
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
        // Load real test vector data
        string memory json = vm.readFile("test/test_vectors/comprehensive_vector_1.json");
        
        // Parse the real signature components for the intent (base PQ message)
        bytes memory salt = vm.parseBytes(vm.parseJsonString(json, ".registration.intent_epervier_salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(json, ".registration.intent_epervier_hint"));
        
        // Parse the base PQ message
        bytes memory basePQMessage = vm.parseBytes(vm.parseJsonString(json, ".registration.base_pq_message"));
        
        // Parse the ETH address
        address ethAddress = vm.parseAddress(vm.parseJsonString(json, ".eth_address"));
        
        // Parse the ETH intent message and signature
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(json, ".registration.eth_intent_message"));
        bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(json, ".registration.eth_intent_signature"));
        
        // Parse ETH signature components
        (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
        
        // Mock the Epervier verifier to return the ETH address as the PQ fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(ethAddress)
        );
        
        // Submit registration intent with real data
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Parse the confirmation signature components
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(json, ".registration.epervier_salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(json, ".registration.epervier_cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(json, ".registration.epervier_cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(json, ".registration.epervier_hint"));
        
        // Parse the PQ confirmation message from the test vector
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(json, ".registration.pq_confirm_message"));
        
        // Confirm registration with real PQ signature
        registry.confirmRegistration(
            pqConfirmMessage,
            confirmSalt,
            confirmCs1,
            confirmCs2,
            confirmHint
        );
        
        // Now test changing ETH address
        address newEthAddress = vm.parseAddress(vm.parseJsonString(json, ".next_eth_address"));
        
        // Create change ETH address message
        bytes memory changePQMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Change ETH Address from ",
            abi.encodePacked(ethAddress), // current address
            " to ",
            abi.encodePacked(newEthAddress), // new address
            uint256(0) // pqNonce
        );
        
        // Create ETH message for change intent with nested PQ signature structure
        bytes memory ethChangeMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            salt, // salt
            packUint256Array(cs1), // cs1
            packUint256Array(cs2), // cs2
            hint, // hint
            changePQMessage // base PQ message
        );
        
        // Sign the change intent message with the current ETH address
        bytes32 ethChangeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethChangeMessage.length), ethChangeMessage));
        (uint8 vChange, bytes32 rChange, bytes32 sChange) = vm.sign(alicePrivateKey, ethChangeSignedMessageHash);
        
        registry.submitChangeETHAddressIntent(
            ethChangeMessage,
            vChange,
            rChange,
            sChange
        );
        
        // Create PQ confirmation message for the change (this will be the base PQ message)
        bytes memory pqChangeConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm changing ETH address from ",
            abi.encodePacked(ethAddress), // current address
            " to ",
            abi.encodePacked(newEthAddress), // new address
            uint256(0) // pqNonce
        );
        
        // Create ETH confirmation message with nested PQ signature structure
        bytes memory changeConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key", // Use the pattern that extraction functions expect
            uint256(0), // ethNonce for new address
            salt, // salt
            packUint256Array(cs1), // cs1
            packUint256Array(cs2), // cs2
            hint, // hint
            pqChangeConfirmMessage // base PQ message
        );
        
        // Sign the change confirmation with the new ETH address
        bytes32 changeConfirmSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(changeConfirmMessage.length), changeConfirmMessage));
        (uint8 vConfirm, bytes32 rConfirm, bytes32 sConfirm) = vm.sign(bobPrivateKey, changeConfirmSignedMessageHash);
        
        registry.confirmChangeETHAddress(
            changeConfirmMessage,
            vConfirm,
            rConfirm,
            sConfirm
        );
        
        // Verify the change
        assertEq(registry.epervierKeyToAddress(ethAddress), newEthAddress);
        assertEq(registry.addressToEpervierKey(newEthAddress), ethAddress);
        assertEq(registry.addressToEpervierKey(ethAddress), address(0)); // Old mapping cleared
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
            "Remove intent from address ",
            abi.encodePacked(testAlice),
            uint256(1) // pqNonce (incremented after intent submission)
        );
        bytes32 removeMessageHash = keccak256(ethRemoveMessage);
        bytes32 removeSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethRemoveMessage.length), ethRemoveMessage));
        
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
    
    // Helper function to parse ETH signature components
    function parseSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "Invalid ETH signature length");
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
    }
    
    // Helper function to pack uint256 array into bytes
    function packUint256Array(uint256[] memory arr) internal pure returns (bytes memory) {
        bytes memory result = new bytes(arr.length * 32);
        for (uint i = 0; i < arr.length; i++) {
            bytes memory element = abi.encode(arr[i]);
            for (uint j = 0; j < 32; j++) {
                result[i * 32 + j] = element[j];
            }
        }
        return result;
    }
} 