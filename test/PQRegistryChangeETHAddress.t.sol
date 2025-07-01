// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// Mock contracts for testing
contract MockConsole {
    function log(string memory) external {}
    function log(string memory, uint256) external {}
    function log(string memory, address) external {}
}

contract PQRegistryChangeETHAddressTest is Test {
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
    
    // Test events for verification
    event ChangeETHAddressIntentSubmitted(address indexed pqFingerprint, address indexed newETHAddress, uint256 ethNonce);
    
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
    
    // Helper function to parse signature
    function parseSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "Invalid signature length");
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid signature 'v' value");
    }
    
    // ============================================================================
    // CHANGE ETH ADDRESS INTENT TESTS
    // ============================================================================
    
    function testChangeETHAddressIntent_AllActors_Success() public {
        // Load intent vectors for registration and change ETH address
        string memory registrationJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmationJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");

        string[] memory actorCycle = new string[](10);
        actorCycle[0] = "alice";
        actorCycle[1] = "bob";
        actorCycle[2] = "charlie";
        actorCycle[3] = "danielle";
        actorCycle[4] = "eve";
        actorCycle[5] = "frank";
        actorCycle[6] = "grace";
        actorCycle[7] = "henry";
        actorCycle[8] = "iris";
        actorCycle[9] = "jack";

        for (uint i = 0; i < actorCycle.length; i++) {
            // Reset state for each iteration
            setUp();

            string memory currentActor = actorCycle[i];
            string memory nextActor = actorCycle[(i + 1) % actorCycle.length];
            Actor memory currentActorData = getActor(currentActor);
            Actor memory nextActorData = getActor(nextActor);

            // Step 1: Register current actor (intent + confirm)
            string memory registrationVectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_message")));
            uint8 vIntent = uint8(vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.v"))));
            uint256 rIntentDecimal = vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.r")));
            uint256 sIntentDecimal = vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.s")));
            bytes32 rIntent = bytes32(rIntentDecimal);
            bytes32 sIntent = bytes32(sIntentDecimal);
            registry.submitRegistrationIntent(ethIntentMessage, vIntent, rIntent, sIntent);
            vm.clearMockedCalls();

            string memory confirmationVectorPath = string.concat(".registration_confirmation[", vm.toString(i), "]");
            bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_message")));
            bytes memory confirmationSalt = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.salt")));
            uint256 confirmationHint = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.hint")));
            string memory confirmationCs1Path = string.concat(confirmationVectorPath, ".pq_signature.cs1");
            uint256[] memory confirmationCs1 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                confirmationCs1[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs1Path, "[", vm.toString(j), "]")));
            }
            string memory confirmationCs2Path = string.concat(confirmationVectorPath, ".pq_signature.cs2");
            uint256[] memory confirmationCs2 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                confirmationCs2[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs2Path, "[", vm.toString(j), "]")));
            }
            registry.confirmRegistration(pqConfirmationMessage, confirmationSalt, confirmationCs1, confirmationCs2, confirmationHint);
            vm.clearMockedCalls();

            // Step 2: Submit change ETH address intent (current -> next)
            string memory changeVectorPath = string.concat(".change_eth_address_intent[", vm.toString(i), "]");
            bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, string.concat(changeVectorPath, ".pq_message")));
            bytes memory salt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, string.concat(changeVectorPath, ".pq_signature.salt")));
            uint256 hint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, string.concat(changeVectorPath, ".pq_signature.hint")));
            string memory cs1Path = string.concat(changeVectorPath, ".pq_signature.cs1");
            uint256[] memory cs1 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cs1[j] = vm.parseUint(vm.parseJsonString(changeIntentJsonData, string.concat(cs1Path, "[", vm.toString(j), "]")));
            }
            string memory cs2Path = string.concat(changeVectorPath, ".pq_signature.cs2");
            uint256[] memory cs2 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cs2[j] = vm.parseUint(vm.parseJsonString(changeIntentJsonData, string.concat(cs2Path, "[", vm.toString(j), "]")));
            }
            registry.submitChangeETHAddressIntent(pqMessage, salt, cs1, cs2, hint);

            // Assert that the intent was created
            (address newETHAddress, , uint256 changeTimestamp, ) = registry.changeETHAddressIntents(currentActorData.pqFingerprint);
            assertEq(newETHAddress, nextActorData.ethAddress, string.concat("Change intent should map ", currentActor, "'s PQ fingerprint to ", nextActor, "'s ETH address"));
            assertGt(changeTimestamp, 0, string.concat("Change intent should have a timestamp for ", currentActor));
        }
    }

    function testChangeETHAddressConfirmation_AllActors_Success() public {
        // Load vectors
        string memory registrationJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmationJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        string memory changeConfirmJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_confirmation_vectors.json");

        string[] memory actorCycle = new string[](10);
        actorCycle[0] = "alice";
        actorCycle[1] = "bob";
        actorCycle[2] = "charlie";
        actorCycle[3] = "danielle";
        actorCycle[4] = "eve";
        actorCycle[5] = "frank";
        actorCycle[6] = "grace";
        actorCycle[7] = "henry";
        actorCycle[8] = "iris";
        actorCycle[9] = "jack";

        for (uint i = 0; i < actorCycle.length; i++) {
            // Reset state for each iteration
            setUp();

            string memory currentActor = actorCycle[i];
            string memory nextActor = actorCycle[(i + 1) % actorCycle.length];
            Actor memory currentActorData = getActor(currentActor);
            Actor memory nextActorData = getActor(nextActor);

            // Step 1: Register current actor (intent + confirm)
            string memory registrationVectorPath = string.concat(".registration_intent[", vm.toString(i), "]");
            bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_message")));
            uint8 vIntent = uint8(vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.v"))));
            uint256 rIntentDecimal = vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.r")));
            uint256 sIntentDecimal = vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.s")));
            bytes32 rIntent = bytes32(rIntentDecimal);
            bytes32 sIntent = bytes32(sIntentDecimal);
            registry.submitRegistrationIntent(ethIntentMessage, vIntent, rIntent, sIntent);
            vm.clearMockedCalls();

            string memory confirmationVectorPath = string.concat(".registration_confirmation[", vm.toString(i), "]");
            bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_message")));
            bytes memory confirmationSalt = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.salt")));
            uint256 confirmationHint = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.hint")));
            string memory confirmationCs1Path = string.concat(confirmationVectorPath, ".pq_signature.cs1");
            uint256[] memory confirmationCs1 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                confirmationCs1[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs1Path, "[", vm.toString(j), "]")));
            }
            string memory confirmationCs2Path = string.concat(confirmationVectorPath, ".pq_signature.cs2");
            uint256[] memory confirmationCs2 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                confirmationCs2[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs2Path, "[", vm.toString(j), "]")));
            }
            registry.confirmRegistration(pqConfirmationMessage, confirmationSalt, confirmationCs1, confirmationCs2, confirmationHint);
            vm.clearMockedCalls();

            // Step 2: Submit change ETH address intent (current -> next)
            string memory changeVectorPath = string.concat(".change_eth_address_intent[", vm.toString(i), "]");
            bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, string.concat(changeVectorPath, ".pq_message")));
            bytes memory salt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, string.concat(changeVectorPath, ".pq_signature.salt")));
            uint256 hint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, string.concat(changeVectorPath, ".pq_signature.hint")));
            string memory cs1Path = string.concat(changeVectorPath, ".pq_signature.cs1");
            uint256[] memory cs1 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cs1[j] = vm.parseUint(vm.parseJsonString(changeIntentJsonData, string.concat(cs1Path, "[", vm.toString(j), "]")));
            }
            string memory cs2Path = string.concat(changeVectorPath, ".pq_signature.cs2");
            uint256[] memory cs2 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cs2[j] = vm.parseUint(vm.parseJsonString(changeIntentJsonData, string.concat(cs2Path, "[", vm.toString(j), "]")));
            }
            registry.submitChangeETHAddressIntent(pqMessage, salt, cs1, cs2, hint);

            // Step 3: Confirm the change using the confirmation vector
            string memory changeConfirmVectorPath = string.concat(".change_eth_address_confirmation[", vm.toString(i), "]");
            bytes memory ethConfirmMessage = vm.parseBytes(vm.parseJsonString(changeConfirmJsonData, string.concat(changeConfirmVectorPath, ".eth_message")));
            uint8 vConfirm = uint8(vm.parseUint(vm.parseJsonString(changeConfirmJsonData, string.concat(changeConfirmVectorPath, ".eth_signature.v"))));
            uint256 rConfirmDecimal = vm.parseUint(vm.parseJsonString(changeConfirmJsonData, string.concat(changeConfirmVectorPath, ".eth_signature.r")));
            uint256 sConfirmDecimal = vm.parseUint(vm.parseJsonString(changeConfirmJsonData, string.concat(changeConfirmVectorPath, ".eth_signature.s")));
            bytes32 rConfirm = bytes32(rConfirmDecimal);
            bytes32 sConfirm = bytes32(sConfirmDecimal);
            registry.confirmChangeETHAddress(ethConfirmMessage, vConfirm, rConfirm, sConfirm);

            // Assert PQ key is now mapped to next actor's ETH address
            address pqFingerprint = currentActorData.pqFingerprint;
            address nextActorEthAddress = nextActorData.ethAddress;
            assertEq(registry.epervierKeyToAddress(pqFingerprint), nextActorEthAddress, string.concat("PQ key should be mapped to ", nextActor, "'s ETH address"));
            assertEq(registry.addressToEpervierKey(nextActorEthAddress), pqFingerprint, string.concat(nextActor, "'s ETH address should be mapped to PQ key"));
            assertEq(registry.addressToEpervierKey(currentActorData.ethAddress), address(0), string.concat(currentActor, "'s ETH address should be cleared"));

            // Assert the intent is cleared
            (address newETHAddress, , uint256 changeTimestamp, ) = registry.changeETHAddressIntents(pqFingerprint);
            assertEq(newETHAddress, address(0), "Change intent should be cleared");
            assertEq(changeTimestamp, 0, "Change intent timestamp should be cleared");

            // Assert nonces increment
            assertEq(registry.pqKeyNonces(pqFingerprint), 4, string.concat("PQ nonce should increment to 4 after confirmation for ", currentActor));
            assertEq(registry.ethNonces(nextActorEthAddress), 2, string.concat(nextActor, "'s ETH nonce should increment to 2 after confirmation"));
        }
    }

    // ============================================================================
    // CANCEL CHANGE ETH ADDRESS INTENT TESTS
    // ============================================================================

    function testCancelChangeETHAddressIntent_AllActors_Success() public {
        // Load intent and cancel vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        string memory cancelPQJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_cancel_pq_vectors.json");
        string memory cancelETHJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_cancel_eth_vectors.json");

        for (uint i = 0; i < actorNames.length; i++) {
            // Reset state for each iteration
            setUp();

            string memory currentActor = actorNames[i];
            string memory nextActor = actorNames[(i + 1) % actorNames.length];
            Actor memory currentActorData = getActor(currentActor);
            Actor memory nextActorData = getActor(nextActor);

            // Step 1: Register current actor
            registerActor(currentActor, i);

            // Step 2: Submit change ETH address intent
            string memory intentVectorPath = string.concat(".change_eth_address_intent[", vm.toString(i), "]");
            bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".pq_message")));
            bytes memory salt = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".pq_signature.salt")));
            uint256 hint = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".pq_signature.hint")));
            string memory cs1Path = string.concat(intentVectorPath, ".pq_signature.cs1");
            uint256[] memory cs1 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cs1[j] = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(cs1Path, "[", vm.toString(j), "]")));
            }
            string memory cs2Path = string.concat(intentVectorPath, ".pq_signature.cs2");
            uint256[] memory cs2 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cs2[j] = vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(cs2Path, "[", vm.toString(j), "]")));
            }
            registry.submitChangeETHAddressIntent(pqMessage, salt, cs1, cs2, hint);

            // Verify intent was created
            (address newETHAddress, , uint256 changeTimestamp, ) = registry.changeETHAddressIntents(currentActorData.pqFingerprint);
            assertEq(newETHAddress, nextActorData.ethAddress, string.concat("Change intent should map ", currentActor, "'s PQ fingerprint to ", nextActor, "'s ETH address"));

            // Step 3a: Cancel the intent using PQ signature
            string memory cancelPQVectorPath = string.concat(".change_eth_address_cancel_pq[", vm.toString(i), "]");
            bytes memory pqCancelMessage = vm.parseBytes(vm.parseJsonString(cancelPQJsonData, string.concat(cancelPQVectorPath, ".pq_message")));
            bytes memory cancelSalt = vm.parseBytes(vm.parseJsonString(cancelPQJsonData, string.concat(cancelPQVectorPath, ".pq_signature.salt")));
            uint256 cancelHint = vm.parseUint(vm.parseJsonString(cancelPQJsonData, string.concat(cancelPQVectorPath, ".pq_signature.hint")));
            string memory cancelCs1Path = string.concat(cancelPQVectorPath, ".pq_signature.cs1");
            uint256[] memory cancelCs1 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cancelCs1[j] = vm.parseUint(vm.parseJsonString(cancelPQJsonData, string.concat(cancelCs1Path, "[", vm.toString(j), "]")));
            }
            string memory cancelCs2Path = string.concat(cancelPQVectorPath, ".pq_signature.cs2");
            uint256[] memory cancelCs2 = new uint256[](32);
            for (uint j = 0; j < 32; j++) {
                cancelCs2[j] = vm.parseUint(vm.parseJsonString(cancelPQJsonData, string.concat(cancelCs2Path, "[", vm.toString(j), "]")));
            }
            
            // Debug: Log current PQ nonce before cancel
            console.log("Current PQ nonce before cancel:", registry.pqKeyNonces(currentActorData.pqFingerprint));
            console.log("PQ cancel message length:", pqCancelMessage.length);
            
            registry.removeChangeETHAddressIntentByPQ(pqCancelMessage, cancelSalt, cancelCs1, cancelCs2, cancelHint);

            // Verify the intent is cleared after PQ cancel
            (address clearedNewETHAddress, , uint256 clearedChangeTimestamp, ) = registry.changeETHAddressIntents(currentActorData.pqFingerprint);
            assertEq(clearedNewETHAddress, address(0), string.concat("Change intent should be cleared after PQ cancel for ", currentActor));
            assertEq(clearedChangeTimestamp, 0, string.concat("Change intent timestamp should be cleared after PQ cancel for ", currentActor));

            // Verify PQ nonce is incremented
            console.log("PQ nonce after cancel:", registry.pqKeyNonces(currentActorData.pqFingerprint));
            assertEq(registry.pqKeyNonces(currentActorData.pqFingerprint), 4, string.concat("PQ nonce should increment to 4 after PQ cancel for ", currentActor));

            // Step 3b: Cancel using ETH signature (without submitting another intent first)
            string memory cancelETHVectorPath = string.concat(".change_eth_address_cancel_eth[", vm.toString(i), "]");
            bytes memory ethCancelMessage = vm.parseBytes(vm.parseJsonString(cancelETHJsonData, string.concat(cancelETHVectorPath, ".eth_message")));
            uint8 vCancel = uint8(vm.parseUint(vm.parseJsonString(cancelETHJsonData, string.concat(cancelETHVectorPath, ".eth_signature.v"))));
            uint256 rCancelDecimal = vm.parseUint(vm.parseJsonString(cancelETHJsonData, string.concat(cancelETHVectorPath, ".eth_signature.r")));
            uint256 sCancelDecimal = vm.parseUint(vm.parseJsonString(cancelETHJsonData, string.concat(cancelETHVectorPath, ".eth_signature.s")));
            bytes32 rCancel = bytes32(rCancelDecimal);
            bytes32 sCancel = bytes32(sCancelDecimal);
            
            // This should revert since there's no pending intent to cancel
            vm.expectRevert("No pending change intent found for PQ fingerprint");
            registry.removeChangeETHAddressIntentByETH(ethCancelMessage, vCancel, rCancel, sCancel);

            console.log("Intent created and cancelled by PQ for", currentActor);
        }
    }

    // Helper function to register an actor
    function registerActor(string memory actorName, uint256 vectorIndex) internal {
        Actor memory actor = getActor(actorName);
        
        // Submit registration intent
        string memory registrationJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmationJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        string memory registrationVectorPath = string.concat(".registration_intent[", vm.toString(vectorIndex), "]");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_message")));
        uint8 vIntent = uint8(vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.v"))));
        uint256 rIntentDecimal = vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.r")));
        uint256 sIntentDecimal = vm.parseUint(vm.parseJsonString(registrationJsonData, string.concat(registrationVectorPath, ".eth_signature.s")));
        bytes32 rIntent = bytes32(rIntentDecimal);
        bytes32 sIntent = bytes32(sIntentDecimal);
        registry.submitRegistrationIntent(ethIntentMessage, vIntent, rIntent, sIntent);
        vm.clearMockedCalls();

        // Confirm registration
        string memory confirmationVectorPath = string.concat(".registration_confirmation[", vm.toString(vectorIndex), "]");
        bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_message")));
        bytes memory confirmationSalt = vm.parseBytes(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.salt")));
        uint256 confirmationHint = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationVectorPath, ".pq_signature.hint")));
        string memory confirmationCs1Path = string.concat(confirmationVectorPath, ".pq_signature.cs1");
        uint256[] memory confirmationCs1 = new uint256[](32);
        for (uint j = 0; j < 32; j++) {
            confirmationCs1[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs1Path, "[", vm.toString(j), "]")));
        }
        string memory confirmationCs2Path = string.concat(confirmationVectorPath, ".pq_signature.cs2");
        uint256[] memory confirmationCs2 = new uint256[](32);
        for (uint j = 0; j < 32; j++) {
            confirmationCs2[j] = vm.parseUint(vm.parseJsonString(confirmationJsonData, string.concat(confirmationCs2Path, "[", vm.toString(j), "]")));
        }
        registry.confirmRegistration(pqConfirmationMessage, confirmationSalt, confirmationCs1, confirmationCs2, confirmationHint);
        vm.clearMockedCalls();
    }
} 