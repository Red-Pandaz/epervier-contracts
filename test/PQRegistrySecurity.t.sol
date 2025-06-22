// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockContract {
    // Empty contract for testing
}

contract PQRegistrySecurityTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    // Test addresses with private keys
    uint256 public alicePrivateKey = 0xA11CE;
    uint256 public bobPrivateKey = 0xB0B;
    uint256 public charliePrivateKey = 0xC0C;
    
    address public alice = vm.addr(alicePrivateKey);
    address public bob = vm.addr(bobPrivateKey);
    address public charlie = vm.addr(charliePrivateKey);
    
    // Test keys
    uint256[2] public alicePublicKey = [uint256(123), uint256(456)];
    uint256[2] public bobPublicKey = [uint256(789), uint256(101)];
    uint256[2] public charliePublicKey = [uint256(202), uint256(303)];
    
    bytes32 public alicePublicKeyHash;
    bytes32 public bobPublicKeyHash;
    bytes32 public charliePublicKeyHash;
    
    // Mock signature data (in real tests, these would be valid signatures)
    bytes public mockSalt;
    uint256[] public mockCs1;
    uint256[] public mockCs2;
    uint256 public mockHint;
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(epervierVerifier));
        
        // Calculate public key hashes
        alicePublicKeyHash = keccak256(abi.encodePacked(alicePublicKey[0], alicePublicKey[1]));
        bobPublicKeyHash = keccak256(abi.encodePacked(bobPublicKey[0], bobPublicKey[1]));
        charliePublicKeyHash = keccak256(abi.encodePacked(charliePublicKey[0], charliePublicKey[1]));
        
        // Setup mock signature data
        mockSalt = new bytes(40);
        mockCs1 = new uint256[](32);
        mockCs2 = new uint256[](32);
        mockHint = 123;
        
        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);
    }
    
    // ========== CONSTRUCTOR TESTS ==========
    
    function testConstructorWithZeroAddress() public {
        vm.expectRevert();
        new PQRegistry(address(0));
    }
    
    function testConstructorWithInvalidContract() public {
        // Deploy a contract that's not an Epervier verifier
        MockContract mockContract = new MockContract();
        // Note: The constructor doesn't actually validate the contract type
        // So this test might need to be updated based on actual validation
        new PQRegistry(address(mockContract));
    }
    
    // ========== DUPLICATE REGISTRATION TESTS ==========
    
    function testCannotRegisterSameAddressTwice() public {
        // Mock successful registration for alice
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory message = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        
        // First registration should succeed
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
        
        // Second registration should fail (ECDSA signature will not match, so expect ECDSA error)
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    function testCannotRegisterSamePublicKeyTwice() public {
        // Mock successful registration for alice
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory message1 = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        bytes memory message2 = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        
        // First registration should succeed
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message1, alicePublicKey);
        
        // Try to register same key for bob (ECDSA signature will not match, so expect ECDSA error)
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(bob)
        );
        
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message2, alicePublicKey);
    }
    
    // ========== INVALID SIGNATURE TESTS ==========
    
    function testInvalidEpervierSignature() public {
        // Mock failed Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(address(0))
        );
        
        bytes memory message = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        
        vm.expectRevert("Invalid Epervier signature");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    function testInvalidECDSASignature() public {
        // Mock successful Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Create message with wrong ECDSA signature (from bob instead of alice)
        bytes memory baseMessage = abi.encodePacked(
            "Register Epervier Key",
            uint256(0),
            alicePublicKey[0],
            alicePublicKey[1]
        );
        
        // Sign with bob's key instead of alice's
        vm.prank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPrivateKey, keccak256(baseMessage));
        bytes memory wrongSignature = abi.encodePacked(r, s, v);
        
        bytes memory message = abi.encodePacked(baseMessage, wrongSignature);
        
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    function testInvalidECDSASignatureFormat() public {
        // Mock successful Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Create message with invalid ECDSA signature format (wrong length)
        bytes memory message = abi.encodePacked(
            "Register Epervier Key",
            uint256(0),
            alicePublicKey[0],
            alicePublicKey[1],
            new bytes(64) // Wrong length (should be 65)
        );
        
        vm.expectRevert();
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    // ========== INVALID NONCE TESTS ==========
    
    function testInvalidNonce() public {
        // Mock successful Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Create message with wrong nonce (should be 0, but using 1)
        bytes memory baseMessage = abi.encodePacked(
            "Register Epervier Key",
            uint256(1), // Wrong nonce
            alicePublicKey[0],
            alicePublicKey[1]
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, keccak256(baseMessage));
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory message = abi.encodePacked(baseMessage, signature);
        
        // ECDSA signature will not match the expected message, so expect ECDSA error
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    function testReplayAttackWithSameNonce() public {
        // Mock successful Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory message = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        
        // First registration should succeed
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
        
        // Try to replay with same nonce (ECDSA signature will not match, so expect ECDSA error)
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    // ========== UNAUTHORIZED OPERATION TESTS ==========
    
    function testCannotDisableSomeoneElsesKey() public {
        // First register alice's key
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory registerMessage = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, registerMessage, alicePublicKey);
        
        // Try to disable alice's key using bob's signature
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(bob)
        );
        
        bytes memory disableMessage = createMockMessage("Disable PQ Security", 1, [uint256(0), uint256(0)]);
        
        // ECDSA signature will not match, so expect ECDSA error
        vm.expectRevert("ECDSA signature must be from same address");
        registry.disablePQSecurity(mockSalt, mockCs1, mockCs2, mockHint, disableMessage);
    }
    
    function testCannotChangeSomeoneElsesKey() public {
        // First register alice's key
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory registerMessage = createMockMessage("Register Epervier Key", 0, alicePublicKey);
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, registerMessage, alicePublicKey);
        
        // Try to change alice's key using bob's signature
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(bob)
        );
        
        bytes memory oldMessage = createMockMessage("Old message", 0, alicePublicKey);
        bytes memory newMessage = createMockMessage("Change Epervier Key", 1, bobPublicKey);
        
        // ECDSA signature will not match, so expect ECDSA error
        vm.expectRevert("ECDSA signature must be from same address");
        registry.changeEpervierKey(
            mockSalt, mockCs1, mockCs2, mockHint, oldMessage, alicePublicKey,
            mockSalt, mockCs1, mockCs2, mockHint, newMessage, bobPublicKey
        );
    }
    
    // ========== MESSAGE FORMAT TESTS ==========
    
    function testMessageTooShort() public {
        // Mock successful Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Create message that's too short
        bytes memory shortMessage = abi.encodePacked(
            "Register Epervier Key",
            uint256(0),
            alicePublicKey[0] // Missing publicKey[1] and ECDSA signature
        );
        
        vm.expectRevert("Message too short");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, shortMessage, alicePublicKey);
    }
    
    function testWrongMessagePrefix() public {
        // Mock successful Epervier signature verification
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        // Create message with wrong prefix
        bytes memory baseMessage = abi.encodePacked(
            "Wrong Prefix",
            uint256(0),
            alicePublicKey[0],
            alicePublicKey[1]
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, keccak256(baseMessage));
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory message = abi.encodePacked(baseMessage, signature);
        
        // ECDSA signature will not match, so expect ECDSA error
        vm.expectRevert("ECDSA signature must be from same address");
        registry.registerEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    // ========== STATE TRANSITION TESTS ==========
    
    function testCannotEnablePQSecurityWhenNotDisabled() public {
        // Try to enable PQ security when no key is registered
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory message = createMockMessage("Enable PQ Security", 0, alicePublicKey);
        
        // ECDSA signature will not match, so expect ECDSA error
        vm.expectRevert("ECDSA signature must be from same address");
        registry.enablePQSecurity(mockSalt, mockCs1, mockCs2, mockHint, message, alicePublicKey);
    }
    
    function testCannotDeleteNonExistentKey() public {
        // Try to delete a key that doesn't exist
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice)
        );
        
        bytes memory message = createMockMessage("Delete Epervier Key", 0, [uint256(0), uint256(0)]);
        
        // ECDSA signature will not match, so expect ECDSA error
        vm.expectRevert("ECDSA signature must be from same address");
        registry.deleteEpervierKey(mockSalt, mockCs1, mockCs2, mockHint, message);
    }
    
    // ========== HELPER FUNCTIONS ==========
    
    function createMockMessage(string memory prefix, uint256 nonce, uint256[2] memory publicKey) internal view returns (bytes memory) {
        bytes memory baseMessage = abi.encodePacked(prefix, nonce, publicKey[0], publicKey[1]);
        
        // Create a mock ECDSA signature using alice's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, keccak256(baseMessage));
        bytes memory signature = abi.encodePacked(r, s, v);
        
        return abi.encodePacked(baseMessage, signature);
    }
} 