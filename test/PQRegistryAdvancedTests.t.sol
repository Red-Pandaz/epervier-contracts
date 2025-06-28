// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";

// Mock for Console
contract MockConsole {
    function log(string memory) external {}
    function log(string memory, uint256) external {}
    function log(string memory, address) external {}
}

contract PQRegistryAdvancedTests is Test {
    using ECDSA for bytes32;
    using Strings for string;
    
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    MockConsole public mockConsole;
    
    // Actor configuration
    struct Actor {
        address ethAddress;
        address pqFingerprint;
        uint256 ethPrivateKey;
        string pqPrivateKeyFile;
        string pqPublicKeyFile;
    }
    
    string[] public actorNames = ["alice", "bob", "charlie", "danielle", "eve", "frank", "grace", "henry", "iris", "jack"];
    
    function setUp() public {
        // Deploy the real Epervier verifier
        epervierVerifier = new ZKNOX_epervier();
        
        // Deploy mock console
        mockConsole = new MockConsole();
        
        // Deploy the registry with real verifier
        registry = new PQRegistry(address(epervierVerifier), address(mockConsole));
    }
    
    /**
     * @dev Get actor configuration by name
     */
    function getActor(string memory name) internal view returns (Actor memory) {
        if (keccak256(bytes(name)) == keccak256(bytes("alice"))) {
            return Actor({
                ethAddress: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,
                pqFingerprint: 0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb,
                ethPrivateKey: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80,
                pqPrivateKeyFile: "test/test_keys/alice_pq_private_key.txt",
                pqPublicKeyFile: "test/test_keys/alice_pq_public_key.txt"
            });
        } else if (keccak256(bytes(name)) == keccak256(bytes("bob"))) {
            return Actor({
                ethAddress: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8,
                pqFingerprint: 0xE6115cDCD7C5df334D05c80787244361e31f0f33,
                ethPrivateKey: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d,
                pqPrivateKeyFile: "test/test_keys/bob_pq_private_key.txt",
                pqPublicKeyFile: "test/test_keys/bob_pq_public_key.txt"
            });
        } else if (keccak256(bytes(name)) == keccak256(bytes("charlie"))) {
            return Actor({
                ethAddress: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,
                pqFingerprint: 0x46f1c659d4e3Ea9671636418A5970a33fe1842fD,
                ethPrivateKey: 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a,
                pqPrivateKeyFile: "test/test_keys/charlie_pq_private_key.txt",
                pqPublicKeyFile: "test/test_keys/charlie_pq_public_key.txt"
            });
        }
        revert("Actor not found");
    }
    
    /**
     * @dev Complete registration for an actor using basic vectors
     */
    function completeRegistration(Actor memory actor, uint256 vectorIndex) internal {
        // Submit intent
        string memory intentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory intentMessage = vm.parseBytes(vm.parseJsonString(intentJson, string.concat(".registration_intent[", vm.toString(vectorIndex), "].eth_message")));
        
        bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(intentMessage.length), intentMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(actor.ethPrivateKey, signedHash);
        
        registry.submitRegistrationIntent(intentMessage, v, r, s);
        
        // Confirm registration
        string memory confirmJson = vm.readFile("test/test_vectors/registration_confirmation_vectors.json");
        bytes memory confirmMessage = vm.parseBytes(vm.parseJsonString(confirmJson, string.concat(".registration_confirmation[", vm.toString(vectorIndex), "].pq_message")));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(confirmJson, string.concat(".registration_confirmation[", vm.toString(vectorIndex), "].pq_signature.salt")));
        uint256[] memory cs1 = vm.parseJsonUintArray(confirmJson, string.concat(".registration_confirmation[", vm.toString(vectorIndex), "].pq_signature.cs1"));
        uint256[] memory cs2 = vm.parseJsonUintArray(confirmJson, string.concat(".registration_confirmation[", vm.toString(vectorIndex), "].pq_signature.cs2"));
        uint256 hint = vm.parseUint(vm.parseJsonString(confirmJson, string.concat(".registration_confirmation[", vm.toString(vectorIndex), "].pq_signature.hint")));
        
        registry.confirmRegistration(confirmMessage, salt, cs1, cs2, hint);
    }

    // Advanced Test 1: ETH Registration - PQ Removes - ETH Retries - PQ Confirms
    function testETHRegistrationWithPQRemovalAndRetry() public {
        // Load the basic vectors we'll use for this test
        string memory intentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        string memory removalJson = vm.readFile("test/test_vectors/registration_pq_removal_vectors.json");
        string memory confirmJson = vm.readFile("test/test_vectors/registration_confirmation_vectors.json");
        string memory advancedJson = vm.readFile("test/test_vectors/advanced/correct_advanced_vectors.json");
        
        // Get Alice's configuration
        Actor memory alice = getActor("alice");
        
        console.log("=== Test 1: ETH Registration - PQ Removes - ETH Retries - PQ Confirms ===");
        console.log("Actor: alice");
        console.log("ETH Address:", alice.ethAddress);
        console.log("PQ Fingerprint:", alice.pqFingerprint);
        
        // Step 1: ETH creates registration intent (nonce 0)
        console.log("\n--- Step 1: ETH creates registration intent ---");
        bytes memory intentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[0].eth_message"));
        bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(intentMessage.length), intentMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice.ethPrivateKey, signedHash);
        
        registry.submitRegistrationIntent(intentMessage, v, r, s);
        
        // Verify intent was created
        (address pendingFingerprint, , uint256 timestamp) = registry.pendingIntents(alice.ethAddress);
        assertEq(pendingFingerprint, alice.pqFingerprint, "Pending intent should be created");
        assertGt(timestamp, 0, "Timestamp should be set");
        assertEq(registry.ethNonces(alice.ethAddress), 1, "ETH nonce should be incremented to 1");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 1, "PQ nonce should be incremented to 1");
        
        console.log("Registration intent created successfully");
        console.log("ETH nonce:", registry.ethNonces(alice.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 2: PQ removes registration intent (nonce 1)
        console.log("\n--- Step 2: PQ removes registration intent ---");
        bytes memory removalMessage = vm.parseBytes(vm.parseJsonString(removalJson, ".registration_pq_removal[0].pq_message"));
        bytes memory removalSalt = vm.parseBytes(vm.parseJsonString(removalJson, ".registration_pq_removal[0].pq_signature.salt"));
        uint256[] memory removalCs1 = vm.parseJsonUintArray(removalJson, ".registration_pq_removal[0].pq_signature.cs1");
        uint256[] memory removalCs2 = vm.parseJsonUintArray(removalJson, ".registration_pq_removal[0].pq_signature.cs2");
        uint256 removalHint = vm.parseUint(vm.parseJsonString(removalJson, ".registration_pq_removal[0].pq_signature.hint"));
        
        registry.removeRegistrationIntentByPQ(removalMessage, removalSalt, removalCs1, removalCs2, removalHint);
        
        // Verify intent was removed
        (address removedFingerprint, , ) = registry.pendingIntents(alice.ethAddress);
        assertEq(removedFingerprint, address(0), "Pending intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), address(0), "Reverse mapping should be cleared");
        assertEq(registry.ethNonces(alice.ethAddress), 1, "ETH nonce should remain at 1 after PQ removal");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 2, "PQ nonce should be incremented to 2");
        
        console.log("Registration intent removed successfully");
        console.log("ETH nonce:", registry.ethNonces(alice.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 3: ETH creates new registration intent (nonce 2)
        console.log("\n--- Step 3: ETH creates new registration intent ---");
        bytes memory newIntentMessage = vm.parseBytes(vm.parseJsonString(advancedJson, ".registration_intent_nonce2[0].eth_message"));
        (uint8 v2, bytes32 r2, bytes32 s2) = (
            uint8(vm.parseUint(vm.parseJsonString(advancedJson, ".registration_intent_nonce2[0].eth_signature.v"))),
            bytes32(vm.parseUint(vm.parseJsonString(advancedJson, ".registration_intent_nonce2[0].eth_signature.r"))),
            bytes32(vm.parseUint(vm.parseJsonString(advancedJson, ".registration_intent_nonce2[0].eth_signature.s")))
        );
        
        registry.submitRegistrationIntent(newIntentMessage, v2, r2, s2);
        
        // Verify new intent was created
        (address newPendingFingerprint, , uint256 newTimestamp) = registry.pendingIntents(alice.ethAddress);
        assertEq(newPendingFingerprint, alice.pqFingerprint, "New pending intent should be created");
        assertGt(newTimestamp, 0, "New timestamp should be set");
        assertEq(registry.ethNonces(alice.ethAddress), 2, "ETH nonce should be incremented to 2");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 3, "PQ nonce should be incremented to 3");
        
        console.log("New registration intent created successfully");
        console.log("ETH nonce:", registry.ethNonces(alice.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 4: PQ confirms registration (nonce 3)
        console.log("\n--- Step 4: PQ confirms registration ---");
        bytes memory confirmMessage = vm.parseBytes(vm.parseJsonString(advancedJson, ".registration_confirmation_nonce3[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(advancedJson, ".registration_confirmation_nonce3[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(advancedJson, ".registration_confirmation_nonce3[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(advancedJson, ".registration_confirmation_nonce3[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(advancedJson, ".registration_confirmation_nonce3[0].pq_signature.hint"));
        
        registry.confirmRegistration(confirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "Registration should be complete");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "Registration should be complete");
        
        // Verify pending intent was cleared
        (address finalPendingFingerprint, , ) = registry.pendingIntents(alice.ethAddress);
        assertEq(finalPendingFingerprint, address(0), "Pending intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(alice.pqFingerprint), address(0), "Pending intent mapping should be cleared");
        
        assertEq(registry.ethNonces(alice.ethAddress), 3, "ETH nonce should be incremented to 3 after confirmation");
        assertEq(registry.pqKeyNonces(alice.pqFingerprint), 4, "PQ nonce should be incremented to 4 after confirmation");
        
        console.log("Registration confirmed successfully");
        console.log("ETH nonce:", registry.ethNonces(alice.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        console.log("Final registration mapping: ETH", alice.ethAddress, "- PQ", alice.pqFingerprint);
        
        console.log("\n=== Test 1 PASSED ===");
    }
}
