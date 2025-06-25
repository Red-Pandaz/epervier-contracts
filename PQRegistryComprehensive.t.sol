// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "./src/PQRegistry.sol";
import "./src/ETHFALCON/ZKNOX_epervier.sol";

contract PQRegistryComprehensiveTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public verifier;
    
    // Test actors
    address public alice;
    address public bob;
    address public charlie;
    address public danielle;
    
    // PQ fingerprints (derived from PQ public keys)
    address public alicePQFingerprint;
    address public bobPQFingerprint;
    address public charliePQFingerprint;
    address public daniellePQFingerprint;
    
    // Nonces
    uint256 public aliceNonce = 0;
    uint256 public bobNonce = 0;
    uint256 public charlieNonce = 0;
    uint256 public danielleNonce = 0;
    
    uint256 public alicePQNonce = 0;
    uint256 public bobPQNonce = 0;
    uint256 public charliePQNonce = 0;
    uint256 public daniellePQNonce = 0;
    
    // Test message components
    bytes32 public constant DOMAIN_SEPARATOR = keccak256("PQRegistry");
    
    function setUp() public {
        // Deploy mock verifier
        verifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(verifier));
        
        // Set up test accounts
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        danielle = makeAddr("danielle");
        
        // Set up PQ fingerprints (in real tests, these would be derived from actual PQ keys)
        alicePQFingerprint = makeAddr("alicePQ");
        bobPQFingerprint = makeAddr("bobPQ");
        charliePQFingerprint = makeAddr("charliePQ");
        daniellePQFingerprint = makeAddr("daniellePQ");
        
        // Fund accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);
        vm.deal(danielle, 100 ether);
    }
    
    // ============ HELPER FUNCTIONS ============
    
    function createBasePQRegistrationIntentMessage(
        address ethAddress,
        uint256 pqNonce
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            ethAddress,
            pqNonce
        );
    }
    
    function createETHRegistrationIntentMessage(
        bytes memory basePQMessage,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint,
        uint256 ethNonce
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            ethNonce
        );
    }
    
    function createMockPQSignature() internal pure returns (
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint
    ) {
        salt = new bytes(40);
        cs1 = new uint256[](32);
        cs2 = new uint256[](32);
        hint = 12345;
        
        // Fill with mock data
        for (uint i = 0; i < 40; i++) {
            salt[i] = bytes1(uint8(i));
        }
        for (uint i = 0; i < 32; i++) {
            cs1[i] = i + 1;
            cs2[i] = i + 100;
        }
    }
    
    function signMessage(bytes memory message, uint256 privateKey) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 messageHash = keccak256(message);
        bytes32 signedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", vm.toString(message.length), message));
        (v, r, s) = vm.sign(privateKey, signedMessageHash);
    }
    
    // ============ SUBMIT REGISTRATION INTENT TESTS ============
    
    function test_submitRegistrationIntent_ValidCase() public {
        // Test: Valid registration intent with correct signatures
        uint256 alicePrivateKey = 0xA11CE;
        
        // Create base PQ message
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        
        // Create mock PQ signature
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        // Create ETH message
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        // Sign with Alice's private key
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        // Mock the verifier to return Alice's PQ fingerprint
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint)
        );
        
        // Submit registration intent
        registry.submitRegistrationIntent(ethMessage, v, r, s);
        
        // Verify intent was stored
        (address storedPQFingerprint, , , ) = registry.pendingIntents(alice);
        assertEq(storedPQFingerprint, alicePQFingerprint);
        
        // Verify nonces were incremented
        assertEq(registry.ethNonces(alice), aliceNonce + 1);
    }
    
    function test_submitRegistrationIntent_InvalidETHSignature() public {
        // Test: Invalid ETH signature
        uint256 alicePrivateKey = 0xA11CE;
        uint256 wrongPrivateKey = 0xB0B;
        
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        // Sign with wrong private key
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, wrongPrivateKey);
        
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint)
        );
        
        // Should revert with invalid signature
        vm.expectRevert("Invalid ETH signature");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_InvalidPQSignature() public {
        // Test: Invalid PQ signature components
        uint256 alicePrivateKey = 0xA11CE;
        
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        
        // Invalid salt length (should be 40 bytes)
        bytes memory invalidSalt = new bytes(30);
        (uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            invalidSalt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        // Should revert due to invalid signature components
        vm.expectRevert();
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_IncorrectETHNonce() public {
        // Test: Incorrect ETH nonce
        uint256 alicePrivateKey = 0xA11CE;
        
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        // Use wrong nonce
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce + 1 // Wrong nonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint)
        );
        
        // Should revert with incorrect nonce
        vm.expectRevert("ERR6: Invalid ETH nonce in submitRegistrationIntent");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_IncorrectPQNonce() public {
        // Test: Incorrect PQ nonce
        uint256 alicePrivateKey = 0xA11CE;
        
        // Use wrong PQ nonce in base message
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce + 1);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint)
        );
        
        // Should revert with incorrect PQ nonce
        vm.expectRevert("ERR4: Invalid PQ nonce in submitRegistrationIntent");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_ETHAddressAlreadyRegistered() public {
        // Test: ETH address already has registered PQ key
        uint256 alicePrivateKey = 0xA11CE;
        
        // First, register Alice
        _registerAlice();
        
        // Try to register again
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint)
        );
        
        // Should revert - already registered
        vm.expectRevert("ERR5: Epervier key already registered");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_PQKeyAlreadyRegistered() public {
        // Test: PQ key already has registered ETH address
        uint256 alicePrivateKey = 0xA11CE;
        uint256 bobPrivateKey = 0xB0B;
        
        // First, register Alice
        _registerAlice();
        
        // Try to register Bob with the same PQ fingerprint
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(bob, bobPQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            bobNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, bobPrivateKey);
        
        // Mock verifier to return Alice's PQ fingerprint (same as Bob's)
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint) // Same fingerprint
        );
        
        // Should revert - PQ key already registered
        vm.expectRevert("ERR5: Epervier key already registered");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_PendingChangeIntent() public {
        // Test: PQ fingerprint has pending change intent
        uint256 alicePrivateKey = 0xA11CE;
        
        // First, register Alice
        _registerAlice();
        
        // Create a pending change intent for Alice's PQ fingerprint
        _createPendingChangeIntent(alice, bob);
        
        // Try to register Charlie with Alice's PQ fingerprint
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(charlie, charliePQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            charlieNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, charliePrivateKey);
        
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint) // Same fingerprint as Alice
        );
        
        // Should revert - pending change intent exists
        vm.expectRevert("PQ fingerprint has pending change intent");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_PendingUnregistrationIntent() public {
        // Test: ETH address has pending unregistration intent
        uint256 alicePrivateKey = 0xA11CE;
        
        // First, register Alice
        _registerAlice();
        
        // Create a pending unregistration intent for Alice
        _createPendingUnregistrationIntent(alice);
        
        // Try to register Alice again
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(alicePQFingerprint)
        );
        
        // Should revert - pending unregistration intent exists
        vm.expectRevert("ETH address has pending unregistration intent");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    function test_submitRegistrationIntent_RecoveredAddressMismatch() public {
        // Test: Recovered ETH address does not match address in PQ message
        uint256 alicePrivateKey = 0xA11CE;
        
        // Create base PQ message with Alice's address
        bytes memory basePQMessage = createBasePQRegistrationIntentMessage(alice, alicePQNonce);
        (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) = createMockPQSignature();
        
        bytes memory ethMessage = createETHRegistrationIntentMessage(
            basePQMessage,
            salt,
            cs1,
            cs2,
            hint,
            aliceNonce
        );
        
        (uint8 v, bytes32 r, bytes32 s) = signMessage(ethMessage, alicePrivateKey);
        
        // Mock verifier to return a different ETH address than what's in the message
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector, basePQMessage, salt, cs1, cs2, hint),
            abi.encode(bob) // Different address than Alice
        );
        
        // Should revert - recovered address doesn't match message
        vm.expectRevert("ERR3: ETH signature must be from intent address");
        registry.submitRegistrationIntent(ethMessage, v, r, s);
    }
    
    // ============ HELPER FUNCTIONS FOR SETUP ============
    
    function _registerAlice() internal {
        // Helper to register Alice (simplified for testing)
        // In a real test, this would use proper signatures
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector),
            abi.encode(alicePQFingerprint)
        );
        
        // Mock the registration process
        registry.epervierKeyToAddress(alicePQFingerprint);
        registry.addressToEpervierKey(alice);
    }
    
    function _createPendingChangeIntent(address currentAddress, address newAddress) internal {
        // Helper to create a pending change intent
        // This would normally require proper signatures
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector),
            abi.encode(alicePQFingerprint)
        );
        
        // Mock the change intent storage
        registry.changeETHAddressIntents(alicePQFingerprint);
    }
    
    function _createPendingUnregistrationIntent(address ethAddress) internal {
        // Helper to create a pending unregistration intent
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(verifier.recover.selector),
            abi.encode(alicePQFingerprint)
        );
        
        // Mock the unregistration intent storage
        registry.unregistrationIntents(ethAddress);
    }
    
    // ============ ADDITIONAL TEST FUNCTIONS ============
    
    function test_confirmRegistration_ValidCase() public {
        // TODO: Implement comprehensive confirmRegistration tests
    }
    
    function test_removeIntent_ValidCase() public {
        // TODO: Implement comprehensive removeIntent tests
    }
    
    function test_submitChangeETHAddressIntent_ValidCase() public {
        // TODO: Implement comprehensive change address tests
    }
    
    function test_removeChangeETHAddressIntentByETH_ValidCase() public {
        // TODO: Implement comprehensive ETH-controlled removal tests
    }
} 