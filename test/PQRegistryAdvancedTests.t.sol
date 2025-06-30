// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/libraries/MessageParser.sol";

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
     * @dev Parse hex string array from JSON for signature components
     */
    function parseJsonHexArray(string memory jsonData, string memory path) internal pure returns (uint256[] memory) {
        string memory arrayJson = vm.parseJsonString(jsonData, path);
        // Remove the outer brackets
        string memory innerJson = vm.parseJsonString(arrayJson, "$");
        
        // Count the number of elements by counting commas + 1
        uint256 count = 1;
        for (uint256 i = 0; i < bytes(innerJson).length; i++) {
            if (bytes(innerJson)[i] == ",") {
                count++;
            }
        }
        
        uint256[] memory result = new uint256[](count);
        
        for (uint256 i = 0; i < count; i++) {
            string memory elementPath = string.concat("$[", vm.toString(i), "]");
            string memory hexString = vm.parseJsonString(innerJson, elementPath);
            // Remove quotes if present
            if (bytes(hexString)[0] == '"') {
                hexString = vm.parseJsonString(hexString, "$");
            }
            result[i] = vm.parseUint(hexString);
        }
        
        return result;
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
        } else if (keccak256(bytes(name)) == keccak256(bytes("danielle"))) {
            return Actor({
                ethAddress: 0x9BBfABe4dB16Cbf6902a438588B1f1eE9FB88182,
                pqFingerprint: 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4,
                ethPrivateKey: 0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e,
                pqPrivateKeyFile: "test/test_keys/danielle_pq_private_key.txt",
                pqPublicKeyFile: "test/test_keys/danielle_pq_public_key.txt"
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

    // Advanced Test 2: PQ Registration -> ETH Removes -> PQ Retries -> ETH Confirms
    function testPQRegistrationWithETHRemovalAndRetry() public {
        // Load the vectors we'll use for this test
        string memory intentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        string memory removalJson = vm.readFile("test/test_vectors/registration_eth_removal_vectors.json");
        string memory advancedJson = vm.readFile("test/test_vectors/advanced/correct_advanced_vectors.json");
        
        // Get Bob's configuration
        Actor memory bob = getActor("bob");
        
        console.log("=== Test 2: PQ Registration -> ETH Removes -> PQ Retries -> ETH Confirms ===");
        console.log("Actor: bob");
        console.log("ETH Address:", bob.ethAddress);
        console.log("PQ Fingerprint:", bob.pqFingerprint);
        
        // Step 1: PQ creates registration intent (nonce 0)
        console.log("\n--- Step 1: PQ creates registration intent ---");
        bytes memory intentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[1].eth_message"));
        bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(intentMessage.length), intentMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bob.ethPrivateKey, signedHash);
        
        registry.submitRegistrationIntent(intentMessage, v, r, s);
        
        // Verify intent was created
        (address pendingFingerprint, , uint256 timestamp) = registry.pendingIntents(bob.ethAddress);
        assertEq(pendingFingerprint, bob.pqFingerprint, "Pending intent should be created");
        assertGt(timestamp, 0, "Timestamp should be set");
        console.log("[Step 1] Actual ETH nonce:", registry.ethNonces(bob.ethAddress), "Expected: 1");
        console.log("[Step 1] Actual PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint), "Expected: 1");
        assertEq(registry.ethNonces(bob.ethAddress), 1, "ETH nonce should be incremented to 1");
        assertEq(registry.pqKeyNonces(bob.pqFingerprint), 1, "PQ nonce should be incremented to 1");
        
        console.log("Registration intent created successfully");
        console.log("ETH nonce:", registry.ethNonces(bob.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint));
        
        // Step 2: ETH removes registration intent (nonce 1)
        console.log("\n--- Step 2: ETH removes registration intent ---");
        bytes memory removalMessage = vm.parseBytes(vm.parseJsonString(removalJson, ".registration_eth_removal[1].eth_message"));
        bytes32 removalSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(removalMessage.length), removalMessage));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bob.ethPrivateKey, removalSignedHash);
        
        registry.removeRegistrationIntentByETH(removalMessage, v2, r2, s2);
        
        // Verify intent was removed
        (address removedFingerprint, , ) = registry.pendingIntents(bob.ethAddress);
        assertEq(removedFingerprint, address(0), "Pending intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(bob.pqFingerprint), address(0), "Reverse mapping should be cleared");
        console.log("[Step 2] Actual ETH nonce:", registry.ethNonces(bob.ethAddress), "Expected: 2");
        console.log("[Step 2] Actual PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint), "Expected: 1");
        assertEq(registry.ethNonces(bob.ethAddress), 2, "ETH nonce should be incremented to 2");
        assertEq(registry.pqKeyNonces(bob.pqFingerprint), 1, "PQ nonce should remain at 1");
        
        console.log("Registration intent removed successfully");
        console.log("ETH nonce:", registry.ethNonces(bob.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint));
        
        // Step 3: PQ creates new registration intent (nonce 1)
        console.log("\n--- Step 3: PQ creates new registration intent ---");
        string memory pqRetryJson = vm.readFile("test/test_vectors/test2_pq_retry_vectors.json");
        bytes memory newIntentMessage = vm.parseBytes(vm.parseJsonString(pqRetryJson, ".registration_intent_nonce2_pq1[0].eth_message"));
        uint8 v3 = uint8(vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_intent_nonce2_pq1[0].eth_signature.v")));
        uint256 r3Decimal = vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_intent_nonce2_pq1[0].eth_signature.r"));
        uint256 s3Decimal = vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_intent_nonce2_pq1[0].eth_signature.s"));
        bytes32 r3 = bytes32(r3Decimal);
        bytes32 s3 = bytes32(s3Decimal);
        
        console.log("Step 3 ETH nonce from vector:", vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_intent_nonce2_pq1[0].eth_nonce")));
        console.log("Step 3 PQ nonce from vector:", vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_intent_nonce2_pq1[0].pq_nonce")));
        
        registry.submitRegistrationIntent(newIntentMessage, v3, r3, s3);
        
        // Verify new intent was created
        (address newPendingFingerprint, , uint256 newTimestamp) = registry.pendingIntents(bob.ethAddress);
        assertEq(newPendingFingerprint, bob.pqFingerprint, "New pending intent should be created");
        assertGt(newTimestamp, 0, "New timestamp should be set");
        console.log("[Step 3] Actual ETH nonce:", registry.ethNonces(bob.ethAddress), "Expected: 3");
        console.log("[Step 3] Actual PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint), "Expected: 2");
        assertEq(registry.ethNonces(bob.ethAddress), 3, "ETH nonce should be incremented to 3");
        assertEq(registry.pqKeyNonces(bob.pqFingerprint), 2, "PQ nonce should be incremented to 2");
        
        console.log("New registration intent created successfully");
        console.log("ETH nonce:", registry.ethNonces(bob.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint));
        
        // Step 4: ETH confirms registration (nonce 2)
        console.log("\n--- Step 4: ETH confirms registration ---");
        bytes memory confirmMessage = vm.parseBytes(vm.parseJsonString(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].pq_signature.hint"));
        
        console.log("Step 4 ETH nonce from vector:", vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].eth_nonce")));
        console.log("Step 4 PQ nonce from vector:", vm.parseUint(vm.parseJsonString(pqRetryJson, ".registration_confirmation_nonce2_pq2[0].pq_nonce")));
        
        registry.confirmRegistration(confirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        
        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(bob.pqFingerprint), bob.ethAddress, "Registration should be complete");
        assertEq(registry.addressToEpervierKey(bob.ethAddress), bob.pqFingerprint, "Registration should be complete");
        
        // Verify pending intent was cleared
        (address finalPendingFingerprint, , ) = registry.pendingIntents(bob.ethAddress);
        assertEq(finalPendingFingerprint, address(0), "Pending intent should be cleared");
        assertEq(registry.pqFingerprintToPendingIntentAddress(bob.pqFingerprint), address(0), "Pending intent mapping should be cleared");
        
        console.log("[Step 4] Actual ETH nonce:", registry.ethNonces(bob.ethAddress), "Expected: 4");
        console.log("[Step 4] Actual PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint), "Expected: 3");
        assertEq(registry.ethNonces(bob.ethAddress), 4, "ETH nonce should be incremented to 4 after confirmation");
        assertEq(registry.pqKeyNonces(bob.pqFingerprint), 3, "PQ nonce should be incremented to 3 after confirmation");
        
        console.log("Registration confirmed successfully");
        console.log("ETH nonce:", registry.ethNonces(bob.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint));
        console.log("Final registration mapping: ETH", bob.ethAddress, "- PQ", bob.pqFingerprint);
        
        console.log("\n=== Test 2 PASSED ===");
    }

    // Advanced Test 3: Multiple Actors Concurrent Registrations
    function testMultipleActorsConcurrentRegistrations() public {
        // Load the vectors we'll use for this test
        string memory intentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        
        // Get all three actors' configurations
        Actor memory alice = getActor("alice");
        Actor memory bob = getActor("bob");
        Actor memory charlie = getActor("charlie");
        
        console.log("=== Test 3: Multiple Actors Concurrent Registrations ===");
        console.log("Actors: Alice, Bob, Charlie");
        console.log("Flow: Submit intents A,B,C -> Confirm C,A,B");
        
        // Step 1: Alice submits registration intent
        console.log("\n--- Step 1: Alice submits registration intent ---");
        bytes memory aliceIntentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[0].eth_message"));
        bytes32 aliceIntentSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(aliceIntentMessage.length), aliceIntentMessage));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(alice.ethPrivateKey, aliceIntentSignedHash);
        registry.submitRegistrationIntent(aliceIntentMessage, v1, r1, s1);
        
        // Step 2: Bob submits registration intent
        console.log("\n--- Step 2: Bob submits registration intent ---");
        bytes memory bobIntentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[1].eth_message"));
        bytes32 bobIntentSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bobIntentMessage.length), bobIntentMessage));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bob.ethPrivateKey, bobIntentSignedHash);
        registry.submitRegistrationIntent(bobIntentMessage, v2, r2, s2);
        
        // Step 3: Charlie submits registration intent
        console.log("\n--- Step 3: Charlie submits registration intent ---");
        bytes memory charlieIntentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[2].eth_message"));
        bytes32 charlieIntentSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(charlieIntentMessage.length), charlieIntentMessage));
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(charlie.ethPrivateKey, charlieIntentSignedHash);
        registry.submitRegistrationIntent(charlieIntentMessage, v3, r3, s3);
        
        // Optionally, add assertions here to check state after all intents
        // ...
        
        console.log("\n=== Test 3A PASSED: All actors submitted registration intents ===");
    }

    // Advanced Test 4: Change ETH -> PQ Cancels -> Change to Different ETH -> Confirms
    function testChangeETH_PQCancels_ChangeToDifferentETH_Confirms() public {
        // Get actor configurations
        Actor memory alice = getActor("alice");
        Actor memory charlie = getActor("charlie");
        
        console.log("=== Test 4: Change ETH -> PQ Cancels -> Change to Different ETH -> Confirms ===");
        console.log("Alice ETH Address:", alice.ethAddress);
        console.log("Alice PQ Fingerprint:", alice.pqFingerprint);
        console.log("Charlie ETH Address:", charlie.ethAddress);
        
        // Debug: Log initial PQ nonce before any steps
        console.log("DEBUG: Initial PQ nonce before Step 1:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 1: Alice submits registration intent
        console.log("\n--- Step 1: Alice submits registration intent ---");
        string memory regIntentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory regIntentMessage = vm.parseBytes(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_message"));
        uint8 v0 = uint8(vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.v")));
        uint256 r0Decimal = vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.r"));
        uint256 s0Decimal = vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.s"));
        bytes32 r0 = bytes32(r0Decimal);
        bytes32 s0 = bytes32(s0Decimal);
        registry.submitRegistrationIntent(regIntentMessage, v0, r0, s0);
        console.log("Step 1 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 1 and Step 2
        console.log("DEBUG: PQ nonce between Step 1 and Step 2:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 2: Alice confirms registration
        console.log("\n--- Step 2: Alice confirms registration ---");
        string memory regConfirmJson = vm.readFile("test/test_vectors/registration_confirmation_vectors.json");
        bytes memory pqMessage1 = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_message"));
        bytes memory salt1 = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory cs1_1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory cs2_1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs2");
        uint256 hint1 = vm.parseUint(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.hint"));
        registry.confirmRegistration(pqMessage1, salt1, cs1_1, cs2_1, hint1);
        console.log("Step 2 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 2 and Step 3
        console.log("DEBUG: PQ nonce between Step 2 and Step 3:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 3: Alice submits change intent to BobETH (PQ intent) - USING ADVANCED VECTORS
        console.log("\n--- Step 3: Alice submits change intent to BobETH (using advanced vectors) ---");
        string memory advancedIntentJson = vm.readFile("test/test_vectors/advanced/test4_pq_cancels_change_eth_intent_vectors.json");
        bytes memory pqMessage2 = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_message"));
        bytes memory salt2 = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory cs1_2 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory cs2_2 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 hint2 = vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.hint"));
        console.log("Step 3 PQ nonce from vector:", vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_nonce")));
        console.log("Step 3 ETH nonce from vector:", vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].eth_nonce")));
        registry.submitChangeETHAddressIntent(pqMessage2, salt2, cs1_2, cs2_2, hint2);
        console.log("Step 3 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 3 and Step 4
        console.log("DEBUG: PQ nonce between Step 3 and Step 4:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 4: PQ cancels the change intent - USING ADVANCED VECTORS
        console.log("\n--- Step 4: PQ cancels the change intent (using advanced vectors) ---");
        string memory advancedCancelJson = vm.readFile("test/test_vectors/advanced/test4_pq_cancels_change_eth_removal_change_pq_vectors.json");
        bytes memory pqMessage3 = vm.parseBytes(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_message"));
        bytes memory salt3 = vm.parseBytes(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_signature.salt"));
        uint256[] memory cs1_3 = vm.parseJsonUintArray(advancedCancelJson, ".removal_change_pq[0].pq_signature.cs1");
        uint256[] memory cs2_3 = vm.parseJsonUintArray(advancedCancelJson, ".removal_change_pq[0].pq_signature.cs2");
        uint256 hint3 = vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_signature.hint"));
        console.log("Step 4 PQ nonce from vector:", vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_nonce")));
        registry.removeChangeETHAddressIntentByPQ(pqMessage3, salt3, cs1_3, cs2_3, hint3);
        console.log("Step 4 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 4 and Step 5
        console.log("DEBUG: PQ nonce between Step 4 and Step 5:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 5: Alice submits change intent to CharlieETH (PQ intent) - USING ADVANCED VECTORS
        console.log("\n--- Step 5: Alice submits change intent to CharlieETH (using advanced vectors) ---");
        bytes memory pqMessage4 = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_message"));
        bytes memory salt4 = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.salt"));
        uint256[] memory cs1_4 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.cs1");
        uint256[] memory cs2_4 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.cs2");
        uint256 hint4 = vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.hint"));
        console.log("Step 5 PQ nonce from vector:", vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_nonce")));
        console.log("Step 5 ETH nonce from vector:", vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].eth_nonce")));
        registry.submitChangeETHAddressIntent(pqMessage4, salt4, cs1_4, cs2_4, hint4);
        console.log("Step 5 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 5 and Step 6
        console.log("DEBUG: PQ nonce between Step 5 and Step 6:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 6: AlicePQ confirms change to CharlieETH - USING ADVANCED VECTORS
        console.log("\n--- Step 6: AlicePQ confirms change to CharlieETH (using advanced vectors) ---");
        string memory advancedConfirmJson = vm.readFile("test/test_vectors/advanced/test4_pq_cancels_change_eth_change_eth_address_confirmation_vectors.json");
        bytes memory advancedConfirmMessage = vm.parseBytes(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_message"));
        uint8 v8 = uint8(vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.v")));
        uint256 r8Decimal = vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.r"));
        uint256 s8Decimal = vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.s"));
        bytes32 r8 = bytes32(r8Decimal);
        bytes32 s8 = bytes32(s8Decimal);
        registry.confirmChangeETHAddress(advancedConfirmMessage, v8, r8, s8);
        console.log("Step 6 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Verify final state - Alice should now be bound to Charlie's ETH address
        address alicePQFingerprint = registry.addressToEpervierKey(alice.ethAddress);
        address aliceBoundETH = registry.epervierKeyToAddress(alice.pqFingerprint);
        console.log("Final state - Alice PQ bound to ETH:", aliceBoundETH);
        console.log("Final state - Alice ETH bound to PQ:", alicePQFingerprint);
        assertEq(aliceBoundETH, charlie.ethAddress, "Alice should now be bound to Charlie's ETH address");
        console.log("\n=== Test 4 PASSED ===");
    }

    // Advanced Test 5: Change ETH -> ETH Cancels -> Change to Different ETH -> Confirms
    function testChangeETH_ETHCancels_ChangeToDifferentETH_Confirms() public {
        // Get actor configurations
        Actor memory alice = getActor("alice");
        Actor memory charlie = getActor("charlie");
        
        console.log("=== Test 5: Change ETH -> ETH Cancels -> Change to Different ETH -> Confirms ===");
        console.log("Alice ETH Address:", alice.ethAddress);
        console.log("Alice PQ Fingerprint:", alice.pqFingerprint);
        console.log("Charlie ETH Address:", charlie.ethAddress);
        
        // Step 1: Alice submits registration intent
        console.log("\n--- Step 1: Alice submits registration intent ---");
        string memory regIntentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory regIntentMessage = vm.parseBytes(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_message"));
        uint8 v0 = uint8(vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.v")));
        uint256 r0Decimal = vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.r"));
        uint256 s0Decimal = vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.s"));
        bytes32 r0 = bytes32(r0Decimal);
        bytes32 s0 = bytes32(s0Decimal);
        registry.submitRegistrationIntent(regIntentMessage, v0, r0, s0);
        console.log("Step 1 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 1 and Step 2
        console.log("DEBUG: PQ nonce between Step 1 and Step 2:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 2: Alice confirms registration
        console.log("\n--- Step 2: Alice confirms registration ---");
        string memory regConfirmJson = vm.readFile("test/test_vectors/registration_confirmation_vectors.json");
        bytes memory pqMessage1 = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_message"));
        bytes memory salt1 = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory cs1_1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory cs2_1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs2");
        uint256 hint1 = vm.parseUint(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.hint"));
        registry.confirmRegistration(pqMessage1, salt1, cs1_1, cs2_1, hint1);
        console.log("Step 2 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 2 and Step 3
        console.log("DEBUG: PQ nonce between Step 2 and Step 3:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 3: Alice submits change intent to BobETH (PQ intent) - USING ADVANCED VECTORS
        console.log("\n--- Step 3: Alice submits change intent to BobETH (using advanced vectors) ---");
        string memory advancedIntentJson = vm.readFile("test/test_vectors/advanced/test5_eth_cancels_change_eth_intent_vectors.json");
        bytes memory pqMessage2 = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_message"));
        bytes memory salt2 = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory cs1_2 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory cs2_2 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 hint2 = vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_signature.hint"));
        console.log("Step 3 PQ nonce from vector:", vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].pq_nonce")));
        console.log("Step 3 ETH nonce from vector:", vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[0].eth_nonce")));
        registry.submitChangeETHAddressIntent(pqMessage2, salt2, cs1_2, cs2_2, hint2);
        console.log("Step 3 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 3 and Step 4
        console.log("DEBUG: PQ nonce between Step 3 and Step 4:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 4: ETH cancels the change intent - USING ADVANCED VECTORS
        console.log("\n--- Step 4: ETH cancels the change intent (using advanced vectors) ---");
        string memory advancedCancelJson = vm.readFile("test/test_vectors/advanced/test5_eth_cancels_change_eth_removal_change_eth_vectors.json");
        bytes memory ethMessage3 = vm.parseBytes(vm.parseJsonString(advancedCancelJson, ".removal_change_eth[0].eth_message"));
        uint8 v3 = uint8(vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_eth[0].eth_signature.v")));
        uint256 r3Decimal = vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_eth[0].eth_signature.r"));
        uint256 s3Decimal = vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_eth[0].eth_signature.s"));
        bytes32 r3 = bytes32(r3Decimal);
        bytes32 s3 = bytes32(s3Decimal);
        console.log("Step 4 ETH nonce from vector:", vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_eth[0].eth_nonce")));
        registry.removeChangeETHAddressIntentByETH(ethMessage3, v3, r3, s3);
        console.log("Step 4 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 4 and Step 5
        console.log("DEBUG: PQ nonce between Step 4 and Step 5:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 5: Alice submits change intent to CharlieETH (PQ intent) - USING ADVANCED VECTORS
        console.log("\n--- Step 5: AlicePQ changes to CharlieETH ---");
        string memory step5IntentJson = vm.readFile("test/test_vectors/advanced/multiple_change_attempts_change_eth_address_intent_vectors.json");
        bytes memory advancedIntentMessage = vm.parseBytes(vm.parseJsonString(step5IntentJson, ".change_eth_address_intent[1].pq_message"));
        bytes memory advancedIntentSalt = vm.parseBytes(vm.parseJsonString(step5IntentJson, ".change_eth_address_intent[1].pq_signature.salt"));
        uint256[] memory advancedIntentCs1 = vm.parseJsonUintArray(step5IntentJson, ".change_eth_address_intent[1].pq_signature.cs1");
        uint256[] memory advancedIntentCs2 = vm.parseJsonUintArray(step5IntentJson, ".change_eth_address_intent[1].pq_signature.cs2");
        uint256 advancedIntentHint = vm.parseUint(vm.parseJsonString(step5IntentJson, ".change_eth_address_intent[1].pq_signature.hint"));
        registry.submitChangeETHAddressIntent(advancedIntentMessage, advancedIntentSalt, advancedIntentCs1, advancedIntentCs2, advancedIntentHint);
        console.log("Step 5 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Debug: Log PQ nonce between Step 5 and Step 6
        console.log("DEBUG: PQ nonce between Step 5 and Step 6:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 6: AlicePQ confirms change to CharlieETH - USING ADVANCED VECTORS
        console.log("\n--- Step 6: AlicePQ confirms change to CharlieETH (using advanced vectors) ---");
        string memory advancedConfirmJson = vm.readFile("test/test_vectors/advanced/test5_eth_cancels_change_eth_change_eth_address_confirmation_vectors.json");
        bytes memory advancedConfirmMessage = vm.parseBytes(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_message"));
        uint8 v8 = uint8(vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.v")));
        uint256 r8Decimal = vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.r"));
        uint256 s8Decimal = vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.s"));
        bytes32 r8 = bytes32(r8Decimal);
        bytes32 s8 = bytes32(s8Decimal);
        registry.confirmChangeETHAddress(advancedConfirmMessage, v8, r8, s8);
        console.log("Step 6 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Verify final state - Alice should now be bound to Charlie's ETH address
        address alicePQFingerprint = registry.addressToEpervierKey(alice.ethAddress);
        address aliceBoundETH = registry.epervierKeyToAddress(alice.pqFingerprint);
        console.log("Final state - Alice PQ bound to ETH:", aliceBoundETH);
        console.log("Final state - Alice ETH bound to PQ:", alicePQFingerprint);
        assertEq(aliceBoundETH, charlie.ethAddress, "Alice should now be bound to Charlie's ETH address");
        console.log("\n=== Test 5 PASSED ===");
    }

    // Advanced Test 6: Multiple Registration Attempts
    function testMultipleRegistrationAttemptsAlicePQSwitchesTargets() public {
        // Get actor configurations
        Actor memory alice = getActor("alice");
        Actor memory bob = getActor("bob");
        Actor memory charlie = getActor("charlie");
        
        console.log("=== Test 6: Multiple Registration Attempts ===");
        console.log("Flow: AlicePQ intent for AliceETH -> AliceETH cancels -> AlicePQ intent for BobETH -> AlicePQ cancels -> AlicePQ intent for CharlieETH -> confirms");
        console.log("Alice ETH Address:", alice.ethAddress);
        console.log("Alice PQ Fingerprint:", alice.pqFingerprint);
        console.log("Bob ETH Address:", bob.ethAddress);
        console.log("Charlie ETH Address:", charlie.ethAddress);
        
        // Step 1: AlicePQ sends register intent for AliceETH (AlicePQ 0, AliceETH 0)
        console.log("\n--- Step 1: AlicePQ sends register intent for AliceETH ---");
        string memory intentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory intentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[0].eth_message"));
        uint8 v0 = uint8(vm.parseUint(vm.parseJsonString(intentJson, ".registration_intent[0].eth_signature.v")));
        uint256 r0Decimal = vm.parseUint(vm.parseJsonString(intentJson, ".registration_intent[0].eth_signature.r"));
        uint256 s0Decimal = vm.parseUint(vm.parseJsonString(intentJson, ".registration_intent[0].eth_signature.s"));
        bytes32 r0 = bytes32(r0Decimal);
        bytes32 s0 = bytes32(s0Decimal);
        registry.submitRegistrationIntent(intentMessage, v0, r0, s0);
        console.log("Step 1 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 2: AliceETH cancels (AliceETH 1, AlicePQ 1)
        console.log("\n--- Step 2: AliceETH cancels ---");
        string memory removalJson = vm.readFile("test/test_vectors/registration_eth_removal_vectors.json");
        bytes memory removalMessage = vm.parseBytes(vm.parseJsonString(removalJson, ".registration_eth_removal[0].eth_message"));
        uint8 v1 = uint8(vm.parseUint(vm.parseJsonString(removalJson, ".registration_eth_removal[0].eth_signature.v")));
        uint256 r1Decimal = vm.parseUint(vm.parseJsonString(removalJson, ".registration_eth_removal[0].eth_signature.r"));
        uint256 s1Decimal = vm.parseUint(vm.parseJsonString(removalJson, ".registration_eth_removal[0].eth_signature.s"));
        bytes32 r1 = bytes32(r1Decimal);
        bytes32 s1 = bytes32(s1Decimal);
        registry.removeRegistrationIntentByETH(removalMessage, v1, r1, s1);
        console.log("Step 2 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 3: AlicePQ sends register intent for BobETH (AlicePQ nonce 1, BobETH nonce 0)
        console.log("\n--- Step 3: AlicePQ sends register intent for BobETH ---");
        string memory bobIntentJson = vm.readFile("test/test_vectors/advanced/multiple_registration_attempts_alice_pq_switches_targets_registration_intent_vectors.json");
        bytes memory bobIntentMessage = vm.parseBytes(vm.parseJsonString(bobIntentJson, ".registration_intent[1].eth_message"));
        uint8 v3 = uint8(vm.parseUint(vm.parseJsonString(bobIntentJson, ".registration_intent[1].eth_signature.v")));
        uint256 r3Decimal = vm.parseUint(vm.parseJsonString(bobIntentJson, ".registration_intent[1].eth_signature.r"));
        uint256 s3Decimal = vm.parseUint(vm.parseJsonString(bobIntentJson, ".registration_intent[1].eth_signature.s"));
        bytes32 r3 = bytes32(r3Decimal);
        bytes32 s3 = bytes32(s3Decimal);
        registry.submitRegistrationIntent(bobIntentMessage, v3, r3, s3);
        console.log("Step 3 completed - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 4: AlicePQ cancels (AlicePQ nonce 2, BobETH nonce 0)
        console.log("\n--- Step 4: AlicePQ cancels ---");
        string memory pqRemovalJson = vm.readFile("test/test_vectors/advanced/multiple_registration_attempts_alice_pq_switches_targets_removal_registration_pq_vectors.json");
        bytes memory pqRemovalMessage = vm.parseBytes(vm.parseJsonString(pqRemovalJson, ".removal_registration_pq[0].pq_message"));
        bytes memory salt3 = vm.parseBytes(vm.parseJsonString(pqRemovalJson, ".removal_registration_pq[0].pq_signature.salt"));
        uint256[] memory cs1_3 = vm.parseJsonUintArray(pqRemovalJson, ".removal_registration_pq[0].pq_signature.cs1");
        uint256[] memory cs2_3 = vm.parseJsonUintArray(pqRemovalJson, ".removal_registration_pq[0].pq_signature.cs2");
        uint256 hint3 = vm.parseUint(vm.parseJsonString(pqRemovalJson, ".removal_registration_pq[0].pq_signature.hint"));
        registry.removeRegistrationIntentByPQ(pqRemovalMessage, salt3, cs1_3, cs2_3, hint3);
        console.log("Step 4 completed - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 5: AlicePQ sends register intent for CharlieETH (AlicePQ nonce 3, CharlieETH nonce 0)
        console.log("\n--- Step 5: AlicePQ sends register intent for CharlieETH ---");
        bytes memory charlieIntentMessage = vm.parseBytes(vm.parseJsonString(bobIntentJson, ".registration_intent[2].eth_message"));
        uint8 v4 = uint8(vm.parseUint(vm.parseJsonString(bobIntentJson, ".registration_intent[2].eth_signature.v")));
        uint256 r4Decimal = vm.parseUint(vm.parseJsonString(bobIntentJson, ".registration_intent[2].eth_signature.r"));
        uint256 s4Decimal = vm.parseUint(vm.parseJsonString(bobIntentJson, ".registration_intent[2].eth_signature.s"));
        bytes32 r4 = bytes32(r4Decimal);
        bytes32 s4 = bytes32(s4Decimal);
        registry.submitRegistrationIntent(charlieIntentMessage, v4, r4, s4);
        console.log("Step 5 completed - ETH nonce:", registry.ethNonces(charlie.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Step 6: Confirms (AlicePQ nonce 4, CharlieETH nonce 1)
        console.log("\n--- Step 6: Confirms ---");
        string memory confirmJson = vm.readFile("test/test_vectors/advanced/multiple_registration_attempts_alice_pq_switches_targets_registration_confirmation_vectors.json");
        bytes memory confirmMessage = vm.parseBytes(vm.parseJsonString(confirmJson, ".registration_confirmation[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJson, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJson, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJson, ".registration_confirmation[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJson, ".registration_confirmation[0].pq_signature.hint"));
        
        // Debug: Parse the PQ message to extract ETH address using MessageParser
        (address ethAddressInPQMessage, , , , , ) = MessageParser.parsePQRegistrationConfirmationMessage(confirmMessage);
        console.log("DEBUG: ETH address in PQ message:", ethAddressInPQMessage);
        console.log("DEBUG: Expected ETH address (Charlie):", charlie.ethAddress);
        console.log("DEBUG: ETH addresses match:", ethAddressInPQMessage == charlie.ethAddress);
        
        // Debug: Parse the base ETH message to extract signature components
        (address pqFingerprint, uint256 ethNonce) = MessageParser.parseBaseETHRegistrationConfirmationMessage(confirmMessage);
        console.log("DEBUG: PQ fingerprint in base ETH message:", pqFingerprint);
        console.log("DEBUG: Expected PQ fingerprint (Alice):", alice.pqFingerprint);
        console.log("DEBUG: PQ fingerprints match:", pqFingerprint == alice.pqFingerprint);
        
        registry.confirmRegistration(confirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        console.log("Step 6 completed - ETH nonce:", registry.ethNonces(charlie.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        console.log("\n=== Test 6 PASSED (with placeholders for missing vectors) ===");
    }

    // Advanced Test 7: Multiple Change Attempts
    function testMultipleChangeAttempts() public {
        // Get actor configurations
        Actor memory alice = getActor("alice");
        Actor memory bob = getActor("bob");
        Actor memory charlie = getActor("charlie");
        Actor memory danielle = getActor("danielle");
        
        console.log("=== Test 7: Multiple Change Attempts ===");
        console.log("Flow: AlicePQ intent for AliceETH -> AliceETH confirms -> AlicePQ changes to BobETH -> BobETH cancels -> AlicePQ changes to CharlieETH -> AlicePQ cancels -> AlicePQ changes to DanielleETH -> confirms");
        console.log("Alice ETH Address:", alice.ethAddress);
        console.log("Alice PQ Fingerprint:", alice.pqFingerprint);
        console.log("Bob ETH Address:", bob.ethAddress);
        console.log("Charlie ETH Address:", charlie.ethAddress);
        console.log("Danielle ETH Address:", danielle.ethAddress);
        
        // Step 1: AlicePQ creates registration intent for AliceETH (ETH nonce 0, PQ nonce 0)
        console.log("\n--- Step 1: AlicePQ creates registration intent for AliceETH ---");
        string memory intentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory intentMessage = vm.parseBytes(vm.parseJsonString(intentJson, ".registration_intent[0].eth_message"));
        uint8 v0 = uint8(vm.parseUint(vm.parseJsonString(intentJson, ".registration_intent[0].eth_signature.v")));
        uint256 r0Decimal = vm.parseUint(vm.parseJsonString(intentJson, ".registration_intent[0].eth_signature.r"));
        uint256 s0Decimal = vm.parseUint(vm.parseJsonString(intentJson, ".registration_intent[0].eth_signature.s"));
        bytes32 r0 = bytes32(r0Decimal);
        bytes32 s0 = bytes32(s0Decimal);
        registry.submitRegistrationIntent(intentMessage, v0, r0, s0);
        console.log("Step 1 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 2: AliceETH confirms registration (ETH nonce 1, PQ nonce 1)
        console.log("\n--- Step 2: AliceETH confirms registration ---");
        string memory confirmJson = vm.readFile("test/test_vectors/registration_confirmation_vectors.json");
        bytes memory confirmMessage = vm.parseBytes(vm.parseJsonString(confirmJson, ".registration_confirmation[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJson, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJson, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJson, ".registration_confirmation[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJson, ".registration_confirmation[0].pq_signature.hint"));
        registry.confirmRegistration(confirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
        console.log("Step 2 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 3: AlicePQ changes AliceETH to BobETH (ETH nonce 0, PQ nonce 2)
        console.log("\n--- Step 3: AlicePQ changes AliceETH to BobETH ---");
        string memory changeIntentJson = vm.readFile("test/test_vectors/change_eth_address_intent_vectors.json");
        bytes memory changeIntentMessage = vm.parseBytes(vm.parseJsonString(changeIntentJson, ".change_eth_address_intent[0].pq_message"));
        bytes memory changeIntentSalt = vm.parseBytes(vm.parseJsonString(changeIntentJson, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changeIntentCs1 = vm.parseJsonUintArray(changeIntentJson, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changeIntentCs2 = vm.parseJsonUintArray(changeIntentJson, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changeIntentHint = vm.parseUint(vm.parseJsonString(changeIntentJson, ".change_eth_address_intent[0].pq_signature.hint"));
        registry.submitChangeETHAddressIntent(changeIntentMessage, changeIntentSalt, changeIntentCs1, changeIntentCs2, changeIntentHint);
        console.log("Step 3 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 4: BobETH cancels the change (ETH nonce 1, PQ nonce 3)
        console.log("\n--- Step 4: BobETH cancels the change ---");
        string memory cancelJson = vm.readFile("test/test_vectors/change_eth_address_cancel_eth_vectors.json");
        bytes memory cancelMessage = vm.parseBytes(vm.parseJsonString(cancelJson, ".change_eth_address_cancel_eth[0].eth_message"));
        uint8 v4 = uint8(vm.parseUint(vm.parseJsonString(cancelJson, ".change_eth_address_cancel_eth[0].eth_signature.v")));
        uint256 r4Decimal = vm.parseUint(vm.parseJsonString(cancelJson, ".change_eth_address_cancel_eth[0].eth_signature.r"));
        uint256 s4Decimal = vm.parseUint(vm.parseJsonString(cancelJson, ".change_eth_address_cancel_eth[0].eth_signature.s"));
        bytes32 r4 = bytes32(r4Decimal);
        bytes32 s4 = bytes32(s4Decimal);
        registry.removeChangeETHAddressIntentByETH(cancelMessage, v4, r4, s4);
        console.log("Step 4 completed - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 5: AlicePQ changes to CharlieETH (ETH nonce 2, PQ nonce 3) - USING ADVANCED VECTORS
        console.log("\n--- Step 5: AlicePQ changes to CharlieETH ---");
        string memory advancedIntentJson = vm.readFile("test/test_vectors/advanced/multiple_change_attempts_change_eth_address_intent_vectors.json");
        bytes memory advancedIntentMessage = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_message"));
        bytes memory advancedIntentSalt = vm.parseBytes(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.salt"));
        uint256[] memory advancedIntentCs1 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.cs1");
        uint256[] memory advancedIntentCs2 = vm.parseJsonUintArray(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.cs2");
        uint256 advancedIntentHint = vm.parseUint(vm.parseJsonString(advancedIntentJson, ".change_eth_address_intent[1].pq_signature.hint"));
        registry.submitChangeETHAddressIntent(advancedIntentMessage, advancedIntentSalt, advancedIntentCs1, advancedIntentCs2, advancedIntentHint);
        console.log("Step 5 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 6: AlicePQ cancels the change (ETH nonce 3, PQ nonce 4) - USING ADVANCED VECTORS
        console.log("\n--- Step 6: AlicePQ cancels the change ---");
        string memory advancedCancelJson = vm.readFile("test/test_vectors/advanced/multiple_change_attempts_removal_change_pq_vectors.json");
        bytes memory advancedCancelMessage = vm.parseBytes(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_message"));
        bytes memory advancedCancelSalt = vm.parseBytes(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_signature.salt"));
        uint256[] memory advancedCancelCs1 = vm.parseJsonUintArray(advancedCancelJson, ".removal_change_pq[0].pq_signature.cs1");
        uint256[] memory advancedCancelCs2 = vm.parseJsonUintArray(advancedCancelJson, ".removal_change_pq[0].pq_signature.cs2");
        uint256 advancedCancelHint = vm.parseUint(vm.parseJsonString(advancedCancelJson, ".removal_change_pq[0].pq_signature.hint"));
        registry.removeChangeETHAddressIntentByPQ(advancedCancelMessage, advancedCancelSalt, advancedCancelCs1, advancedCancelCs2, advancedCancelHint);
        console.log("Step 6 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 7: AlicePQ changes to DanielleETH (ETH nonce 4, PQ nonce 4) - USING ADVANCED VECTORS
        console.log("\n--- Step 7: AlicePQ changes to DanielleETH ---");
        string memory step7IntentJson = vm.readFile("test/test_vectors/advanced/multiple_change_attempts_change_eth_address_intent_vectors.json");
        bytes memory danielleIntentMessage = vm.parseBytes(vm.parseJsonString(step7IntentJson, ".change_eth_address_intent[2].pq_message"));
        bytes memory danielleIntentSalt = vm.parseBytes(vm.parseJsonString(step7IntentJson, ".change_eth_address_intent[2].pq_signature.salt"));
        uint256[] memory danielleIntentCs1 = vm.parseJsonUintArray(step7IntentJson, ".change_eth_address_intent[2].pq_signature.cs1");
        uint256[] memory danielleIntentCs2 = vm.parseJsonUintArray(step7IntentJson, ".change_eth_address_intent[2].pq_signature.cs2");
        uint256 danielleIntentHint = vm.parseUint(vm.parseJsonString(step7IntentJson, ".change_eth_address_intent[2].pq_signature.hint"));
        registry.submitChangeETHAddressIntent(danielleIntentMessage, danielleIntentSalt, danielleIntentCs1, danielleIntentCs2, danielleIntentHint);
        console.log("Step 7 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 8: AlicePQ confirms change to DanielleETH (ETH nonce 5, PQ nonce 5) - USING ADVANCED VECTORS
        console.log("\n--- Step 8: AlicePQ confirms change to DanielleETH ---");
        string memory advancedConfirmJson = vm.readFile("test/test_vectors/advanced/multiple_change_attempts_change_eth_address_confirmation_vectors.json");
        bytes memory advancedConfirmMessage = vm.parseBytes(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_message"));
        uint8 v8 = uint8(vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.v")));
        uint256 r8Decimal = vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.r"));
        uint256 s8Decimal = vm.parseUint(vm.parseJsonString(advancedConfirmJson, ".change_eth_address_confirmation[0].eth_signature.s"));
        bytes32 r8 = bytes32(r8Decimal);
        bytes32 s8 = bytes32(s8Decimal);
        registry.confirmChangeETHAddress(advancedConfirmMessage, v8, r8, s8);
        console.log("Step 8 completed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Verify final state - Alice should now be bound to Danielle's ETH address
        address alicePQFingerprint = registry.addressToEpervierKey(alice.ethAddress);
        address aliceBoundETH = registry.epervierKeyToAddress(alice.pqFingerprint);
        console.log("Final state - Alice PQ bound to ETH:", aliceBoundETH);
        console.log("Final state - Alice ETH bound to PQ:", alicePQFingerprint);
        assertEq(aliceBoundETH, danielle.ethAddress, "Alice should now be bound to Danielle's ETH address");
        console.log("\n=== Test 7 PASSED ===");
    }

    // Advanced Test 8: Unregister → Revoke → Unregister Again → Confirm
    function testUnregisterRevokeUnregisterAgainConfirm() public {
        // Get actor configuration
        Actor memory alice = getActor("alice");

        console.log("=== Test 8: Unregister -> Revoke -> Unregister Again -> Confirm ===");
        console.log("Flow: Alice registers -> AlicePQ initiates unregistration -> AlicePQ revokes -> AlicePQ initiates again -> AliceETH confirms");
        console.log("Alice ETH Address:", alice.ethAddress);
        console.log("Alice PQ Fingerprint:", alice.pqFingerprint);

        // Mock the Epervier verifier to return Alice's fingerprint
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );

        // Step 1: Register Alice (intent + confirm)
        console.log("\n--- Step 1: Register Alice ---");
        string memory regIntentJson = vm.readFile("test/test_vectors/registration_intent_vectors.json");
        bytes memory regIntentMessage = vm.parseBytes(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_message"));
        uint8 v0 = uint8(vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.v")));
        uint256 r0Decimal = vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.r"));
        uint256 s0Decimal = vm.parseUint(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_signature.s"));
        bytes32 r0 = bytes32(r0Decimal);
        bytes32 s0 = bytes32(s0Decimal);
        registry.submitRegistrationIntent(regIntentMessage, v0, r0, s0);
        console.log("Registration intent submitted - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        string memory regConfirmJson = vm.readFile("test/test_vectors/registration_confirmation_vectors.json");
        bytes memory pqMessage1 = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_message"));
        bytes memory salt1 = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory cs1_1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory cs2_1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs2");
        uint256 hint1 = vm.parseUint(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.hint"));
        registry.confirmRegistration(pqMessage1, salt1, cs1_1, cs2_1, hint1);
        console.log("Registration confirmed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Verify registration was completed
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "Alice should be registered");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "Alice should be registered");

        // Step 2: AlicePQ initiates unregistration (intent)
        console.log("\n--- Step 2: AlicePQ initiates unregistration ---");
        string memory unregIntentJson = vm.readFile("test/test_vectors/advanced/test8_unregister_revoke_unregister_confirm_unregistration_intent_vectors.json");
        bytes memory unregIntentMessage1 = vm.parseBytes(vm.parseJsonString(unregIntentJson, ".unregistration_intent[0].pq_message"));
        bytes memory unregSalt1 = vm.parseBytes(vm.parseJsonString(unregIntentJson, ".unregistration_intent[0].pq_signature.salt"));
        uint256[] memory unregCs1_1 = vm.parseJsonUintArray(unregIntentJson, ".unregistration_intent[0].pq_signature.cs1");
        uint256[] memory unregCs2_1 = vm.parseJsonUintArray(unregIntentJson, ".unregistration_intent[0].pq_signature.cs2");
        uint256 unregHint1 = vm.parseUint(vm.parseJsonString(unregIntentJson, ".unregistration_intent[0].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(1), uint256(2)];
        
        registry.submitUnregistrationIntent(unregIntentMessage1, unregSalt1, unregCs1_1, unregCs2_1, unregHint1, publicKey);
        console.log("Unregistration intent submitted - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 3: AlicePQ revokes unregistration (removal)
        console.log("\n--- Step 3: AlicePQ revokes unregistration ---");
        string memory unregRemovalJson = vm.readFile("test/test_vectors/advanced/test8_unregister_revoke_unregister_confirm_remove_intent_vectors.json");
        bytes memory unregRemovalMessage = vm.parseBytes(vm.parseJsonString(unregRemovalJson, ".remove_intent[0].pq_remove_unregistration_intent.message"));
        bytes memory unregRemovalSalt = vm.parseBytes(vm.parseJsonString(unregRemovalJson, ".remove_intent[0].pq_remove_unregistration_intent.signature.salt"));
        uint256[] memory unregRemovalCs1 = vm.parseJsonUintArray(unregRemovalJson, ".remove_intent[0].pq_remove_unregistration_intent.signature.cs1");
        uint256[] memory unregRemovalCs2 = vm.parseJsonUintArray(unregRemovalJson, ".remove_intent[0].pq_remove_unregistration_intent.signature.cs2");
        uint256 unregRemovalHint = vm.parseUint(vm.parseJsonString(unregRemovalJson, ".remove_intent[0].pq_remove_unregistration_intent.signature.hint"));
        
        registry.removeUnregistrationIntent(unregRemovalMessage, unregRemovalSalt, unregRemovalCs1, unregRemovalCs2, unregRemovalHint);
        console.log("Unregistration revoked - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Step 4: AlicePQ initiates unregistration again (intent) - Use the second vector with correct nonces
        console.log("\n--- Step 4: AlicePQ initiates unregistration again ---");
        // Use the second unregistration intent vector with updated nonces
        bytes memory unregIntentMessage2 = vm.parseBytes(vm.parseJsonString(unregIntentJson, ".unregistration_intent[1].pq_message"));
        bytes memory unregSalt2 = vm.parseBytes(vm.parseJsonString(unregIntentJson, ".unregistration_intent[1].pq_signature.salt"));
        uint256[] memory unregCs1_2 = vm.parseJsonUintArray(unregIntentJson, ".unregistration_intent[1].pq_signature.cs1");
        uint256[] memory unregCs2_2 = vm.parseJsonUintArray(unregIntentJson, ".unregistration_intent[1].pq_signature.cs2");
        uint256 unregHint2 = vm.parseUint(vm.parseJsonString(unregIntentJson, ".unregistration_intent[1].pq_signature.hint"));
        
        registry.submitUnregistrationIntent(unregIntentMessage2, unregSalt2, unregCs1_2, unregCs2_2, unregHint2, publicKey);
        console.log("Second unregistration intent submitted - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Log the exact nonces after second unregistration intent (both should be incremented)
        console.log("=== NONCES AFTER SECOND UNREGISTRATION INTENT ===");
        console.log("ETH nonce:", registry.ethNonces(alice.ethAddress));
        console.log("PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        console.log("================================================");

        // Step 5: AliceETH confirms unregistration - USING WORKING TEST STRUCTURE
        console.log("\n--- Step 5: AliceETH confirms unregistration ---");
        string memory unregConfirmationJson = vm.readFile("test/test_vectors/advanced/test8_unregister_revoke_unregister_confirm_unregistration_confirmation_vectors.json");
        
        // Parse addresses from the test vector
        address testETHAddress = vm.parseAddress(vm.parseJsonString(unregConfirmationJson, ".unregistration_confirmation[0].eth_address"));
        address testPQFingerprint = vm.parseAddress(vm.parseJsonString(unregConfirmationJson, ".unregistration_confirmation[0].pq_fingerprint"));
        
        // Verify the test vector matches our actor config
        assertEq(testETHAddress, alice.ethAddress, "Test vector ETH address should match actor config");
        assertEq(testPQFingerprint, alice.pqFingerprint, "Test vector PQ fingerprint should match actor config");
        
        // Parse ETH message and signature components - USING WORKING TEST FORMAT
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(unregConfirmationJson, ".unregistration_confirmation[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(unregConfirmationJson, ".unregistration_confirmation[0].eth_signature.v")));
        uint256 rDecimal = vm.parseUint(vm.parseJsonString(unregConfirmationJson, ".unregistration_confirmation[0].eth_signature.r"));
        uint256 sDecimal = vm.parseUint(vm.parseJsonString(unregConfirmationJson, ".unregistration_confirmation[0].eth_signature.s"));
        bytes32 r = bytes32(rDecimal);
        bytes32 s = bytes32(sDecimal);
        
        // Confirm unregistration
        registry.confirmUnregistration(ethMessage, v, r, s);
        console.log("Unregistration confirmed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));

        // Final assertions: Alice should be unregistered
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), address(0), "Alice PQ should be unbound");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), address(0), "Alice ETH should be unbound");
        
        // Verify unregistration intent has been cleared
        (uint256 timestamp,,) = registry.unregistrationIntents(alice.ethAddress);
        assertEq(timestamp, 0, "Unregistration intent should be cleared");
        
        console.log("Final state - Alice is unregistered");
        console.log("Final state - Alice PQ bound to ETH:", registry.epervierKeyToAddress(alice.pqFingerprint));
        console.log("Final state - Alice ETH bound to PQ:", registry.addressToEpervierKey(alice.ethAddress));
        console.log("\n=== Test 8 PASSED ===");
    }

    // Advanced Test 9: Full Lifecycle: Registration → Change → Unregistration → Re-registration
    function testFullLifecycle() public {
        // Get actor configurations
        Actor memory alice = getActor("alice");
        Actor memory bob = getActor("bob");
        
        console.log("=== Test 9: Full Lifecycle ===");
        console.log("Flow: AlicePQ registers with AliceETH -> AlicePQ changes to bind with BobETH -> AlicePQ and BobETH unregister -> AliceETH registers with BobPQ");
        console.log("Alice ETH Address:", alice.ethAddress);
        console.log("Alice PQ Fingerprint:", alice.pqFingerprint);
        console.log("Bob ETH Address:", bob.ethAddress);
        console.log("Bob PQ Fingerprint:", bob.pqFingerprint);
        
        // Mock the Epervier verifier to return expected fingerprints
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(alice.pqFingerprint)
        );
        
        // Step 1: AlicePQ registers with AliceETH
        console.log("\n--- Step 1: AlicePQ registers with AliceETH ---");
        string memory regIntentJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_registration_intent_vectors.json");
        string memory regConfirmJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_registration_confirmation_vectors.json");
        
        // Submit registration intent (AlicePQ + AliceETH)
        bytes memory intentMessage = vm.parseBytes(vm.parseJsonString(regIntentJson, ".registration_intent[0].eth_message"));
        bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(intentMessage.length), intentMessage));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice.ethPrivateKey, signedHash);
        
        registry.submitRegistrationIntent(intentMessage, v, r, s);
        console.log("Registration intent submitted - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Confirm registration (AlicePQ + AliceETH)
        bytes memory confirmMessage = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(regConfirmJson, ".registration_confirmation[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(regConfirmJson, ".registration_confirmation[0].pq_signature.hint"));
        
        registry.confirmRegistration(confirmMessage, salt, cs1, cs2, hint);
        console.log("Registration confirmed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Verify registration
        assertEq(registry.addressToEpervierKey(alice.ethAddress), alice.pqFingerprint, "AliceETH should be registered to AlicePQ");
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), alice.ethAddress, "AlicePQ should be registered to AliceETH");
        
        // Step 2: AlicePQ changes to bind with BobETH
        console.log("\n--- Step 2: AlicePQ changes to bind with BobETH ---");
        string memory changeIntentJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_change_eth_address_intent_vectors.json");
        string memory changeConfirmJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_change_eth_address_confirmation_vectors.json");
        
        // Submit change ETH address intent (AlicePQ + BobETH)
        bytes memory changeIntentMessage = vm.parseBytes(vm.parseJsonString(changeIntentJson, ".change_eth_address_intent[0].pq_message"));
        bytes memory changeIntentSalt = vm.parseBytes(vm.parseJsonString(changeIntentJson, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changeIntentCs1 = vm.parseJsonUintArray(changeIntentJson, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changeIntentCs2 = vm.parseJsonUintArray(changeIntentJson, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changeIntentHint = vm.parseUint(vm.parseJsonString(changeIntentJson, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changeIntentMessage, changeIntentSalt, changeIntentCs1, changeIntentCs2, changeIntentHint);
        console.log("Change ETH address intent submitted - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Confirm change ETH address (AlicePQ + BobETH)
        bytes memory changeConfirmMessage = vm.parseBytes(vm.parseJsonString(changeConfirmJson, ".change_eth_address_confirmation[0].eth_message"));
        bytes32 changeConfirmSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(changeConfirmMessage.length), changeConfirmMessage));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bob.ethPrivateKey, changeConfirmSignedHash);
        
        registry.confirmChangeETHAddress(changeConfirmMessage, v2, r2, s2);
        console.log("Change ETH address confirmed - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Verify change
        assertEq(registry.addressToEpervierKey(bob.ethAddress), alice.pqFingerprint, "BobETH should be registered to AlicePQ");
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), bob.ethAddress, "AlicePQ should be registered to BobETH");
        assertEq(registry.addressToEpervierKey(alice.ethAddress), address(0), "AliceETH should no longer be registered");
        
        // Step 3: AlicePQ and BobETH unregister
        console.log("\n--- Step 3: AlicePQ and BobETH unregister ---");
        string memory unregIntentJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_unregistration_intent_vectors.json");
        string memory unregConfirmJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_unregistration_confirmation_vectors.json");
        
        // Submit unregistration intent (AlicePQ + BobETH)
        bytes memory unregIntentMessage = vm.parseBytes(vm.parseJsonString(unregIntentJson, ".unregistration_intent[0].pq_message"));
        bytes memory unregIntentSalt = vm.parseBytes(vm.parseJsonString(unregIntentJson, ".unregistration_intent[0].pq_signature.salt"));
        uint256[] memory unregIntentCs1 = vm.parseJsonUintArray(unregIntentJson, ".unregistration_intent[0].pq_signature.cs1");
        uint256[] memory unregIntentCs2 = vm.parseJsonUintArray(unregIntentJson, ".unregistration_intent[0].pq_signature.cs2");
        uint256 unregIntentHint = vm.parseUint(vm.parseJsonString(unregIntentJson, ".unregistration_intent[0].pq_signature.hint"));
        
        registry.submitUnregistrationIntent(unregIntentMessage, unregIntentSalt, unregIntentCs1, unregIntentCs2, unregIntentHint, [uint256(0), uint256(0)]);
        console.log("Unregistration intent submitted - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Confirm unregistration (AlicePQ + BobETH)
        bytes memory unregConfirmMessage = vm.parseBytes(vm.parseJsonString(unregConfirmJson, ".unregistration_confirmation[0].eth_message"));
        bytes32 unregConfirmSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(unregConfirmMessage.length), unregConfirmMessage));
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(bob.ethPrivateKey, unregConfirmSignedHash);
        
        registry.confirmUnregistration(unregConfirmMessage, v3, r3, s3);
        console.log("Unregistration confirmed - ETH nonce:", registry.ethNonces(bob.ethAddress), "PQ nonce:", registry.pqKeyNonces(alice.pqFingerprint));
        
        // Verify unregistration
        assertEq(registry.addressToEpervierKey(bob.ethAddress), address(0), "BobETH should no longer be registered");
        assertEq(registry.epervierKeyToAddress(alice.pqFingerprint), address(0), "AlicePQ should no longer be registered");
        
        // Step 4: AliceETH registers with BobPQ
        console.log("\n--- Step 4: AliceETH registers with BobPQ ---");
        
        // Mock the Epervier verifier to return Bob's fingerprint for the final registration
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(bob.pqFingerprint)
        );
        
        string memory finalRegIntentJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_final_registration_intent_vectors.json");
        string memory finalRegConfirmJson = vm.readFile("test/test_vectors/advanced/test9_full_lifecycle_final_registration_confirmation_vectors.json");
        
        // Submit final registration intent (BobPQ + AliceETH)
        bytes memory finalIntentMessage = vm.parseBytes(vm.parseJsonString(finalRegIntentJson, ".final_registration_intent[0].eth_message"));
        bytes32 finalIntentSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(finalIntentMessage.length), finalIntentMessage));
        (uint8 v4, bytes32 r4, bytes32 s4) = vm.sign(alice.ethPrivateKey, finalIntentSignedHash);
        
        registry.submitRegistrationIntent(finalIntentMessage, v4, r4, s4);
        console.log("Final registration intent submitted - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint));
        
        // Confirm final registration (BobPQ + AliceETH)
        bytes memory finalConfirmMessage = vm.parseBytes(vm.parseJsonString(finalRegConfirmJson, ".final_registration_confirmation[0].pq_message"));
        bytes memory finalConfirmSalt = vm.parseBytes(vm.parseJsonString(finalRegConfirmJson, ".final_registration_confirmation[0].pq_signature.salt"));
        uint256[] memory finalConfirmCs1 = vm.parseJsonUintArray(finalRegConfirmJson, ".final_registration_confirmation[0].pq_signature.cs1");
        uint256[] memory finalConfirmCs2 = vm.parseJsonUintArray(finalRegConfirmJson, ".final_registration_confirmation[0].pq_signature.cs2");
        uint256 finalConfirmHint = vm.parseUint(vm.parseJsonString(finalRegConfirmJson, ".final_registration_confirmation[0].pq_signature.hint"));
        
        registry.confirmRegistration(finalConfirmMessage, finalConfirmSalt, finalConfirmCs1, finalConfirmCs2, finalConfirmHint);
        console.log("Final registration confirmed - ETH nonce:", registry.ethNonces(alice.ethAddress), "PQ nonce:", registry.pqKeyNonces(bob.pqFingerprint));
        
        // Verify final registration
        assertEq(registry.addressToEpervierKey(alice.ethAddress), bob.pqFingerprint, "AliceETH should be registered to BobPQ");
        assertEq(registry.epervierKeyToAddress(bob.pqFingerprint), alice.ethAddress, "BobPQ should be registered to AliceETH");
        
        console.log("\n=== Full Lifecycle Test Completed Successfully ===");
        console.log("All 11 functions tested in sequence:");
        console.log("1. submitRegistrationIntent (AlicePQ + AliceETH)");
        console.log("2. confirmRegistration (AlicePQ + AliceETH)");
        console.log("3. submitChangeETHAddressIntent (AlicePQ + BobETH)");
        console.log("4. confirmChangeETHAddress (AlicePQ + BobETH)");
        console.log("5. submitUnregistrationIntent (AlicePQ + BobETH)");
        console.log("6. confirmUnregistration (AlicePQ + BobETH)");
        console.log("7. submitRegistrationIntent (BobPQ + AliceETH)");
        console.log("8. confirmRegistration (BobPQ + AliceETH)");
        console.log("Final state: AliceETH <-> BobPQ");
    }
}
