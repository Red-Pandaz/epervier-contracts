// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {PQRegistry} from "../src/PQRegistry.sol";
import {ZKNOX_epervier} from "../ETHFALCON/src/ZKNOX_epervier.sol";
import {MessageParser} from "../src/libraries/MessageParser.sol";

contract PQRegistryRegistrationRevertsTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    // Actor data structure
    struct Actor {
        address ethAddress;
        address pqFingerprint;
        uint256 ethPrivateKey;
        string pqPrivateKeyPath;
    }
    
    // Test actors
    Actor public alice;
    
    // Actor names for test vectors
    string[] public actorNames = ["alice"];
    
    function setUp() public {
        // Deploy the Epervier verifier
        epervierVerifier = new ZKNOX_epervier();
        
        // Deploy the registry
        registry = new PQRegistry(address(epervierVerifier));
        
        // Initialize Alice's data
        alice = Actor({
            ethAddress: 0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb,
            pqFingerprint: 0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb,
            ethPrivateKey: 0x1234567890123456789012345678901234567890123456789012345678901234,
            pqPrivateKeyPath: "test/test_keys/alice_pq_private_key.pem"
        });
    }
    
    function getActor(string memory actorName) internal view returns (Actor memory) {
        if (keccak256(abi.encodePacked(actorName)) == keccak256(abi.encodePacked("alice"))) {
            return alice;
        }
        revert("Unknown actor");
    }
    
    // Helper function to register an actor (for setup)
    function registerActor(Actor memory actor, string memory actorName) internal {
        // Load registration intent vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Find the correct vector index for this actor
        uint256 vectorIndex = 0; // For now, assume alice is at index 0
        
        // Submit registration intent
        string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(vectorIndex), "]");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_message")));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.r")));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.s")));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Confirm registration
        string memory confirmVectorPath = string.concat(".registration_confirmation[", vm.toString(vectorIndex), "]");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_message")));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.salt")));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.cs1"));
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.cs2"));
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.hint")));
        
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    // ============================================================================
    // SUBMIT REGISTRATION INTENT REVERT TESTS
    // ============================================================================
    
    function testSubmitRegistrationIntent_RevertWhenETHAddressAlreadyHasIntent() public {
        // First, submit a valid registration intent using Alice's working vector
        string memory aliceJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory aliceEthIntentMessage = vm.parseBytes(vm.parseJsonString(aliceJsonData, ".registration_intent[0].eth_message"));
        uint8 aliceV = uint8(vm.parseUint(vm.parseJsonString(aliceJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 aliceR = vm.parseBytes32(vm.parseJsonString(aliceJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 aliceS = vm.parseBytes32(vm.parseJsonString(aliceJsonData, ".registration_intent[0].eth_signature.s"));
        
        // First, submit a registration intent (this should succeed)
        registry.submitRegistrationIntent(aliceEthIntentMessage, aliceV, aliceR, aliceS);
        
        // Now try to submit another intent with Alice's ETH address but Bob's PQ fingerprint
        // This should revert because Alice's ETH address already has a pending intent
        string memory jsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[6].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[6].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[6].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[6].eth_signature.s"));
        
        // This should revert because Alice's ETH address already has a pending intent
        vm.expectRevert("ETH Address has pending registration intent");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenPQFingerprintAlreadyHasIntent() public {
        // Load revert test vector for Bob
        string memory jsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[1].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[1].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[1].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[1].eth_signature.s"));
        
        // First, submit a registration intent with Bob's data
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Try to submit another intent with a different ETH address but same PQ fingerprint
        // This should revert because the PQ fingerprint already has a pending intent
        vm.expectRevert("ETH Address has pending registration intent");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenETHAddressAlreadyRegistered() public {
        // First, register Bob completely (Bob's ETH address is now registered to Bob's PQ)
        // Use Bob's registration intent vector from the working vectors
        string memory bobIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory bobEthIntentMessage = vm.parseBytes(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_message"));
        uint8 bobV = uint8(vm.parseUint(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.v")));
        bytes32 bobR = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.r"));
        bytes32 bobS = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.s"));
        
        // Submit Bob's registration intent
        registry.submitRegistrationIntent(bobEthIntentMessage, bobV, bobR, bobS);
        
        // Confirm Bob's registration
        string memory bobConfirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        bytes memory bobPqConfirmMessage = vm.parseBytes(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_message"));
        bytes memory bobConfirmSalt = vm.parseBytes(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.salt"));
        uint256[] memory bobConfirmCs1 = vm.parseJsonUintArray(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.cs1");
        uint256[] memory bobConfirmCs2 = vm.parseJsonUintArray(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.cs2");
        uint256 bobConfirmHint = vm.parseUint(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.hint"));
        
        registry.confirmRegistration(bobPqConfirmMessage, bobConfirmSalt, bobConfirmCs1, bobConfirmCs2, bobConfirmHint);
        
        // Now try to submit a registration intent for Bob's ETH address with Alice's PQ fingerprint
        // This should revert because Bob's ETH address is already registered
        string memory revertJsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory bobEthAlicePqIntentMessage = vm.parseBytes(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_signature.s"));
        
        // This should revert because Bob's ETH address is already registered
        vm.expectRevert("ETH address already registered");
        registry.submitRegistrationIntent(bobEthAlicePqIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenPQFingerprintAlreadyRegistered() public {
        // First, register Alice completely (Alice's PQ fingerprint is now registered to Alice's ETH)
        // Use Alice's registration intent vector from the working vectors
        string memory aliceIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory aliceEthIntentMessage = vm.parseBytes(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_message"));
        uint8 aliceV = uint8(vm.parseUint(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 aliceR = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 aliceS = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.s"));
        
        // Submit Alice's registration intent
        registry.submitRegistrationIntent(aliceEthIntentMessage, aliceV, aliceR, aliceS);
        
        // Confirm Alice's registration
        string memory aliceConfirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        bytes memory alicePqConfirmMessage = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_message"));
        bytes memory aliceConfirmSalt = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory aliceConfirmCs1 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory aliceConfirmCs2 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 aliceConfirmHint = vm.parseUint(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        registry.confirmRegistration(alicePqConfirmMessage, aliceConfirmSalt, aliceConfirmCs1, aliceConfirmCs2, aliceConfirmHint);
        
        // Now try to register Alice's PQ fingerprint with Bob's ETH address
        // This should revert because Alice's PQ fingerprint is already registered
        string memory revertJsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory alicePqBobEthIntentMessage = vm.parseBytes(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(revertJsonData, ".submit_registration_intent_reverts[5].eth_signature.s"));
        
        vm.expectRevert("PQ fingerprint already registered");
        registry.submitRegistrationIntent(alicePqBobEthIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenInvalidETHSignature() public {
        // Load valid intent data
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Use invalid signature components
        uint8 v = 27; // Invalid v value
        bytes32 r = bytes32(0x1234567890123456789012345678901234567890123456789012345678901234);
        bytes32 s = bytes32(0x5678901234567890123456789012345678901234567890123456789012345678);
        
        // This should revert due to invalid ETH signature
        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenWrongETHNonce() public {
        // Load revert test vector with wrong ETH nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[3].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[3].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[3].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[3].eth_signature.s"));
        
        // Try to submit with wrong nonce (should fail)
        vm.expectRevert("Invalid ETH nonce");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenWrongPQNonce() public {
        // Load revert test vector with wrong PQ nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[4].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[4].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[4].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[4].eth_signature.s"));
        
        // Try to submit with wrong PQ nonce (should fail)
        vm.expectRevert("Invalid PQ nonce");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenRecoveredETHAddressMismatch() public {
        // Use a valid vector but modify the ETH signature to be signed by the wrong key
        // This creates a scenario where PQ message contains Alice's ETH address
        // but ETH signature is signed by Bob's private key
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        
        // Load Bob's private key and sign the same message with Bob's key instead of Alice's
        string memory actorsJsonData = vm.readFile("test/test_keys/actors_config.json");
        string memory bobPrivateKeyStr = vm.parseJsonString(actorsJsonData, ".actors.bob.eth_private_key");
        
        // Parse the ETH message to extract the struct hash
        // The message format is: "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
        bytes memory pattern = "Intent to pair Epervier Key";
        uint256 patternLength = 27;
        
        // Extract basePQMessage (111 bytes after pattern)
        bytes memory basePQMessage = new bytes(111);
        for (uint i = 0; i < 111; i++) {
            basePQMessage[i] = ethIntentMessage[patternLength + i];
        }
        
        // Extract other components
        bytes memory salt = new bytes(40);
        for (uint i = 0; i < 40; i++) {
            salt[i] = ethIntentMessage[patternLength + 111 + i];
        }
        
        uint256[] memory cs1 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs1Element = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs1Element[j] = ethIntentMessage[patternLength + 111 + 40 + i * 32 + j];
            }
            cs1[i] = uint256(bytes32(cs1Element));
        }
        
        uint256[] memory cs2 = new uint256[](32);
        for (uint i = 0; i < 32; i++) {
            bytes memory cs2Element = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                cs2Element[j] = ethIntentMessage[patternLength + 111 + 40 + 1024 + i * 32 + j];
            }
            cs2[i] = uint256(bytes32(cs2Element));
        }
        
        bytes memory hintBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            hintBytes[i] = ethIntentMessage[patternLength + 111 + 40 + 1024 + 1024 + i];
        }
        uint256 hint = uint256(bytes32(hintBytes));
        
        bytes memory ethNonceBytes = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            ethNonceBytes[i] = ethIntentMessage[patternLength + 111 + 40 + 1024 + 1024 + 32 + i];
        }
        uint256 ethNonce = uint256(bytes32(ethNonceBytes));
        
        // Create the struct hash
        uint256[32] memory cs1Array;
        uint256[32] memory cs2Array;
        for (uint256 i = 0; i < 32; i++) {
            cs1Array[i] = cs1[i];
            cs2Array[i] = cs2[i];
        }
        
        bytes32 structHash = keccak256(abi.encodePacked(
            keccak256("RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)"),
            keccak256(salt),
            keccak256(abi.encodePacked(cs1Array)),
            keccak256(abi.encodePacked(cs2Array)),
            hint,
            keccak256(basePQMessage),
            ethNonce
        ));
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash));
        
        // Sign with Bob's private key (wrong signer)
        bytes32 bobPrivateKeyBytes = vm.parseBytes32(bobPrivateKeyStr);
        uint256 bobPrivateKey = uint256(bobPrivateKeyBytes);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPrivateKey, digest);
        
        // This should revert because Bob's signature doesn't match Alice's address in PQ message
        vm.expectRevert("ETH signature must be from intent address");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    function testSubmitRegistrationIntent_RevertWhenWrongDomainSeparatorInPQMessage() public {
        // Load revert test vector for wrong DS in PQ message
        string memory jsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[8].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[8].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[8].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[8].eth_signature.s"));

        // This should revert due to wrong domain separator in PQ message
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }

    function testSubmitRegistrationIntent_RevertWhenWrongDomainSeparatorInETHSignature() public {
        // Load revert test vector for wrong DS in ETH signature
        string memory jsonData = vm.readFile("test/test_vectors/revert/submit_registration_intent_revert_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[9].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[9].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[9].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(jsonData, ".submit_registration_intent_reverts[9].eth_signature.s"));

        // This should revert due to wrong domain separator in ETH signature
        // The wrong domain separator causes the ETH signature to recover to a different address
        vm.expectRevert("ETH signature must be from intent address");
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
    }
    
    // ============================================================================
    // CONFIRM REGISTRATION REVERT TESTS  
    // ============================================================================
    
    function testConfirmRegistration_RevertWhenNoPendingIntent() public {
        // Try to confirm registration without submitting an intent first
        string memory jsonData = vm.readFile("test/test_vectors/revert/confirm_registration_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_signature.hint"));
        
        // This should revert because there's no pending intent
        vm.expectRevert("Invalid PQ registration confirmation message");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongPQSignature() public {
        // First submit a registration intent
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Try to confirm with invalid PQ signature
        string memory confirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".registration_confirmation[0].pq_message"));
        
        // Use invalid signature components
        bytes memory invalidSalt = new bytes(32);
        uint256[] memory invalidCs1 = new uint256[](32);
        uint256[] memory invalidCs2 = new uint256[](32);
        uint256 invalidHint = 0;
        
        // This should revert due to invalid PQ signature
        vm.expectRevert("wrong salt length");
        registry.confirmRegistration(pqConfirmMessage, invalidSalt, invalidCs1, invalidCs2, invalidHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongPQNonce() public {
        // First submit a registration intent
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Try to confirm with wrong PQ nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/confirm_registration_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[1].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[1].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[1].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[1].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[1].pq_signature.hint"));
        
        vm.expectRevert("Invalid PQ registration confirmation message");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    // TODO: Add intent expiration test when the feature is implemented
    // function testConfirmRegistration_RevertWhenIntentExpired() public {
    //     // This test requires an expiration mechanism to be added to the contract
    // }
    
    // ============================================================================
    // REMOVE REGISTRATION INTENT BY ETH REVERT TESTS
    // ============================================================================
    
    // TODO: Add revert tests for removeRegistrationIntentByETH()
    
    // ============================================================================
    // REMOVE REGISTRATION INTENT BY PQ REVERT TESTS
    // ============================================================================
    
    // TODO: Add revert tests for removeRegistrationIntentByPQ()
} 