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
        
        // Log Alice's ETH address from the intent
        address aliceEthAddress = vm.parseAddress(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_address"));
        console.log("Alice's ETH address:", aliceEthAddress);
        
        // Log Alice's PQ fingerprint from the intent
        address alicePQFingerprint = vm.parseAddress(vm.parseJsonString(intentJsonData, ".registration_intent[0].pq_fingerprint"));
        console.log("Alice's PQ fingerprint:", alicePQFingerprint);
        
        // Check Alice's PQ nonce before submission
        uint256 alicePQNonceBefore = registry.pqKeyNonces(alicePQFingerprint);
        console.log("Alice's PQ nonce before submission:", alicePQNonceBefore);
        
        // Check Alice's PQ nonce after submission
        uint256 alicePQNonceAfter = registry.pqKeyNonces(alicePQFingerprint);
        console.log("Alice's PQ nonce after submission:", alicePQNonceAfter);
        
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
    
    function testSubmitRegistrationIntent_RevertWhenBobETHAddressInvolvedInPendingChangeIntent() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
        // Use working vectors from registration_intent_vectors.json and registration_confirmation_vectors.json
        string memory aliceIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory aliceConfirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Submit Alice's registration intent (index 0)
        bytes memory aliceEthIntentMessage = vm.parseBytes(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_message"));
        uint8 aliceV = uint8(vm.parseUint(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 aliceR = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 aliceS = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(aliceEthIntentMessage, aliceV, aliceR, aliceS);
        
        // Confirm Alice's registration (index 0)
        bytes memory alicePqConfirmMessage = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_message"));
        bytes memory aliceConfirmSalt = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory aliceConfirmCs1 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory aliceConfirmCs2 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 aliceConfirmHint = vm.parseUint(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        registry.confirmRegistration(alicePqConfirmMessage, aliceConfirmSalt, aliceConfirmCs1, aliceConfirmCs2, aliceConfirmHint);
        
        // Step 2: BobETH and AlicePQ open change ETH intent
        // Use working vectors from change_eth_address_intent_vectors.json
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        
        // Submit change intent (index 0 - BobETH + AlicePQ)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changeSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changeCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changeCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changeHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changeSalt, changeCs1, changeCs2, changeHint);
        
        // Step 3: BobETH and BobPQ attempt to submit a registration intent (SHOULD REVERT)
        // Use Bob's registration intent from working vectors (index 1)
        bytes memory bobEthIntentMessage = vm.parseBytes(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[1].eth_message"));
        uint8 bobV = uint8(vm.parseUint(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[1].eth_signature.v")));
        bytes32 bobR = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[1].eth_signature.r"));
        bytes32 bobS = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[1].eth_signature.s"));
        
        // This should revert because Bob's ETH address is involved in Alice's pending change intent
        vm.expectRevert("ETH Address has pending change intent");
        registry.submitRegistrationIntent(bobEthIntentMessage, bobV, bobR, bobS);
    }
    
    // ============================================================================
    // CONFIRM REGISTRATION REVERT TESTS  
    // ============================================================================
    
    function testConfirmRegistration_RevertWhenNoPendingIntent() public {
        // Load revert test vector for no pending intent
        string memory jsonData = vm.readFile("test/test_vectors/revert/confirm_registration_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_signature.hint"));
        
        // This should revert because there's no pending intent
        vm.expectRevert("No pending intent found for PQ fingerprint");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongPQNonce() public {
        // Load revert test vector for wrong PQ nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[1].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[1].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[1].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[1].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[1].pq_signature.hint"));
        
        // This should revert because the PQ nonce is wrong
        vm.expectRevert("No pending intent found for PQ fingerprint");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongDomainSeparator() public {
        // Load revert test vector for wrong domain separator
        string memory jsonData = vm.readFile("test/test_vectors/revert/confirm_registration_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[2].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[2].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[2].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[2].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[2].pq_signature.hint"));
        
        // This should revert because the domain separator is wrong
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongMessageFormat() public {
        // Load revert test vector for wrong message format
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[3].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[3].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[3].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[3].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[3].pq_signature.hint"));
        
        // This should revert because the message format is wrong
        vm.expectRevert("Invalid PQ registration confirmation message");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenMalformedMessage() public {
        // Load revert test vector for malformed message
        string memory jsonData = vm.readFile("test/test_vectors/revert/comprehensive_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[0].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[0].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[0].pq_signature.hint"));
        
        // This should revert because the message is malformed
        vm.expectRevert("Invalid PQ registration confirmation message");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenInvalidETHSignature() public {
        // Load revert test vector for invalid ETH signature
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[4].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[4].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[4].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[4].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[4].pq_signature.hint"));
        
        // This should revert because the ETH signature is invalid
        vm.expectRevert("ETH Address mismatch: PQ message vs recovered ETH signature");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongETHSigner() public {
        // Load revert test vector for wrong ETH signer
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[5].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[5].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[5].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[5].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[5].pq_signature.hint"));
        
        // This should revert because the ETH signer is wrong
        vm.expectRevert("ETH Address mismatch: PQ message vs recovered ETH signature");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongPQSigner() public {
        // Load revert test vector for wrong PQ signer
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[6].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[6].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[6].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[6].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[6].pq_signature.hint"));
        
        // This should revert because the PQ signer is wrong
        vm.expectRevert("PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenWrongETHNonce() public {
        // Load revert test vector for wrong ETH nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[7].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[7].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[7].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[7].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[7].pq_signature.hint"));
        
        // This should revert because the ETH nonce is wrong
        vm.expectRevert("No pending intent found for PQ fingerprint");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConfirmRegistration_RevertWhenPQFingerprintMismatch() public {
        // Load revert test vector for PQ fingerprint mismatch
        string memory jsonData = vm.readFile("test/test_vectors/revert/missing_confirm_revert_vectors.json");
        bytes memory pqConfirmMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[9].pq_message"));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_registration_reverts[9].pq_signature.salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[9].pq_signature.cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(jsonData, ".confirm_registration_reverts[9].pq_signature.cs2");
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(jsonData, ".confirm_registration_reverts[9].pq_signature.hint"));
        
        // This should revert because the PQ fingerprint doesn't match
        vm.expectRevert("PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        registry.confirmRegistration(pqConfirmMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    // ============================================================================
    // REMOVE REGISTRATION INTENT BY ETH REVERT TESTS
    // ============================================================================
    
    function testRemoveRegistrationIntentByETH_RevertWhenWrongDomainSeparator() public {
        // First, submit a registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Log Alice's ETH address from the intent
        address aliceEthAddress = vm.parseAddress(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_address"));
        console.log("Alice's ETH address:", aliceEthAddress);
        
        // Log Alice's PQ fingerprint from the intent
        address alicePQFingerprint = vm.parseAddress(vm.parseJsonString(intentJsonData, ".registration_intent[0].pq_fingerprint"));
        console.log("Alice's PQ fingerprint:", alicePQFingerprint);
        
        // Check Alice's PQ nonce before submission
        uint256 alicePQNonceBefore = registry.pqKeyNonces(alicePQFingerprint);
        console.log("Alice's PQ nonce before submission:", alicePQNonceBefore);
        
        // Check Alice's PQ nonce after submission
        uint256 alicePQNonceAfter = registry.pqKeyNonces(alicePQFingerprint);
        console.log("Alice's PQ nonce after submission:", alicePQNonceAfter);
        
        // Load a valid remove intent vector but with wrong domain separator
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[1].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[1].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[1].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[1].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // The contract will fail at state validation first (wrong domain separator recovers different address)
        vm.expectRevert("No pending intent found for recovered ETH Address");
        registry.removeRegistrationIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenWrongNonce() public {
        // First, submit a registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load a valid remove intent vector but with wrong nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[2].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[2].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[2].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[2].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        vm.expectRevert("Invalid ETH nonce");
        registry.removeRegistrationIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenWrongSigner() public {
        // First, submit a registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load a valid remove intent vector but signed by wrong ETH key
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[3].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[3].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[3].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[3].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // The contract will fail at state validation first (wrong signer recovers different address)
        vm.expectRevert("No pending intent found for recovered ETH Address");
        registry.removeRegistrationIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenNoPendingIntent() public {
        // Try to remove an intent when none exists for the ETH address
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[0].eth_signature.v")));
        uint256 rDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[0].eth_signature.r"));
        uint256 sDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[0].eth_signature.s"));
        bytes32 r = bytes32(rDecimal);
        bytes32 s = bytes32(sDecimal);
        
        // The contract will fail at state validation first (no pending intent for recovered address)
        vm.expectRevert("No pending intent found for recovered ETH Address");
        registry.removeRegistrationIntentByETH(ethMessage, v, r, s);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenMalformedMessage() public {
        // Use a message that is too short or missing fields
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[4].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[4].eth_signature.v")));
        uint256 rDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[4].eth_signature.r"));
        uint256 sDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[4].eth_signature.s"));
        bytes32 r = bytes32(rDecimal);
        bytes32 s = bytes32(sDecimal);
        
        // The contract will fail at field extraction - message is exactly pattern length, missing fields
        vm.expectRevert("Field extends beyond message length");
        registry.removeRegistrationIntentByETH(ethMessage, v, r, s);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenReplay() public {
        // First, submit a registration intent
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Now remove the intent successfully using the working removal vector
        string memory removalJsonData = vm.readFile("test/test_vectors/register/registration_eth_removal_vectors.json");
        bytes memory ethRemoveMessage = vm.parseBytes(vm.parseJsonString(removalJsonData, ".registration_eth_removal[0].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(removalJsonData, ".registration_eth_removal[0].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(removalJsonData, ".registration_eth_removal[0].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(removalJsonData, ".registration_eth_removal[0].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        registry.removeRegistrationIntentByETH(ethRemoveMessage, vRemove, rRemove, sRemove);
        
        // Try to remove the same intent again (replay attack)
        vm.expectRevert("No pending intent found for recovered ETH Address");
        registry.removeRegistrationIntentByETH(ethRemoveMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenInvalidSignature() public {
        // Load a valid remove intent vector but with invalid signature components
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[5].eth_message"));
        
        // Use invalid signature components
        uint8 v = 27; // Invalid v value
        bytes32 r = bytes32(0x1234567890123456789012345678901234567890123456789012345678901234);
        bytes32 s = bytes32(0x5678901234567890123456789012345678901234567890123456789012345678);
        
        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        registry.removeRegistrationIntentByETH(ethMessage, v, r, s);
    }
    
    function testRemoveRegistrationIntentByETH_RevertWhenWrongPQFingerprint() public {
        // First, submit a registration intent
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Try to remove with wrong PQ fingerprint in message
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethRemoveMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[6].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[6].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[6].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[6].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // The contract will fail at state validation first (wrong PQ fingerprint)
        // The recovered ETH address is correct, but the PQ fingerprint in the message doesn't match
        // the stored intent, so it fails with "PQ fingerprint mismatch"
        vm.expectRevert("PQ fingerprint mismatch: ETH message vs stored intent");
        registry.removeRegistrationIntentByETH(ethRemoveMessage, vRemove, rRemove, sRemove);
    }
    
    // ============================================================================
    // REMOVE REGISTRATION INTENT BY PQ REVERT TESTS
    // ============================================================================
    
    function testRemoveRegistrationIntentByPQ_RevertWhenWrongDomainSeparator() public {
        // First, submit a registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        // Log Alice's ETH address from the intent
        address aliceEthAddress = vm.parseAddress(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_address"));
        console.log("Alice's ETH address:", aliceEthAddress);
        
        // Log Alice's PQ fingerprint from the intent
        address alicePQFingerprint = vm.parseAddress(vm.parseJsonString(intentJsonData, ".registration_intent[0].pq_fingerprint"));
        console.log("Alice's PQ fingerprint:", alicePQFingerprint);
        
        // Check Alice's PQ nonce before submission
        uint256 alicePQNonceBefore = registry.pqKeyNonces(alicePQFingerprint);
        console.log("Alice's PQ nonce before submission:", alicePQNonceBefore);
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Check Alice's PQ nonce after submission
        uint256 alicePQNonceAfter = registry.pqKeyNonces(alicePQFingerprint);
        console.log("Alice's PQ nonce after submission:", alicePQNonceAfter);
        
        // Load a valid remove intent vector but with wrong domain separator
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[1].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[1].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[1].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[1].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[1].pq_signature.hint"));
        
        // Log the expected nonce from the test vector
        uint256 expectedNonce = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[1].pq_nonce"));
        console.log("Expected nonce from test vector:", expectedNonce);
        
        // Log the actual nonce that would be extracted from the message
        uint256 actualNonce = MessageParser.extractPQNonceFromRemoveMessage(pqMessage);
        console.log("Actual nonce extracted from message:", actualNonce);
        
        // Log the PQ fingerprint that would be recovered
        address pqFingerprint = registry.epervierVerifier().recover(pqMessage, salt, cs1, cs2, hint);
        console.log("Recovered PQ fingerprint:", pqFingerprint);
        
        // Log the current nonce for this PQ fingerprint in the registry
        uint256 currentNonce = registry.pqKeyNonces(pqFingerprint);
        console.log("Current nonce in registry for this fingerprint:", currentNonce);
        
        // The contract will fail at message format validation first (wrong domain separator)
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.removeRegistrationIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenWrongNonce() public {
        // First, submit a registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load a valid remove intent vector but with wrong nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[2].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[2].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[2].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[2].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[2].pq_signature.hint"));
        
        vm.expectRevert("Invalid PQ nonce");
        registry.removeRegistrationIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenWrongSigner() public {
        // First, submit a registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load a valid remove intent vector but signed by wrong PQ key
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[3].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[3].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[3].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[3].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[3].pq_signature.hint"));
        
        // The contract will fail at state validation first (wrong signer recovers different fingerprint)
        vm.expectRevert("No pending intent found for this PQ fingerprint");
        registry.removeRegistrationIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenNoPendingIntent() public {
        // Try to remove an intent when none exists for the PQ fingerprint
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[0].pq_signature.hint"));
        
        // The contract will fail at state validation first (no pending intent for recovered fingerprint)
        vm.expectRevert("No pending intent found for this PQ fingerprint");
        registry.removeRegistrationIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenMalformedMessage() public {
        // Use a message that is too short or missing fields
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[4].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[4].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[4].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[4].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[4].pq_signature.hint"));
        
        // The contract will fail at length validation first (message too short)
        // The message is only 26 bytes, but the contract requires at least 128 bytes
        vm.expectRevert("Message too short for PQ nonce from remove message");
        registry.removeRegistrationIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenReplay() public {
        // First, submit a registration intent
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Now remove the intent successfully using PQ
        string memory removalJsonData = vm.readFile("test/test_vectors/register/registration_pq_removal_vectors.json");
        bytes memory pqRemoveMessage = vm.parseBytes(vm.parseJsonString(removalJsonData, ".registration_pq_removal[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removalJsonData, ".registration_pq_removal[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removalJsonData, ".registration_pq_removal[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removalJsonData, ".registration_pq_removal[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removalJsonData, ".registration_pq_removal[0].pq_signature.hint"));
        
        registry.removeRegistrationIntentByPQ(pqRemoveMessage, salt, cs1, cs2, hint);
        
        // Try to remove the same intent again (replay attack)
        vm.expectRevert("No pending intent found for this PQ fingerprint");
        registry.removeRegistrationIntentByPQ(pqRemoveMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenInvalidSignature() public {
        // Load a valid remove intent vector but with invalid signature components
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[5].pq_message"));
        
        // Use invalid signature components
        bytes memory invalidSalt = new bytes(32); // Wrong length
        uint256[] memory invalidCs1 = new uint256[](32);
        uint256[] memory invalidCs2 = new uint256[](32);
        uint256 invalidHint = 0;
        
        vm.expectRevert("wrong salt length");
        registry.removeRegistrationIntentByPQ(pqMessage, invalidSalt, invalidCs1, invalidCs2, invalidHint);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenWrongMessageFormat() public {
        // Load revert test vector for wrong message format
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqRemoveMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[5].pq_message"));
        bytes memory removeSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[5].pq_signature.salt"));
        uint256[] memory removeCs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[5].pq_signature.cs1");
        uint256[] memory removeCs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[5].pq_signature.cs2");
        uint256 removeHint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[5].pq_signature.hint"));
        
        // This should revert because the message format is wrong
        vm.expectRevert("No pending intent found for this PQ fingerprint");
        registry.removeRegistrationIntentByPQ(pqRemoveMessage, removeSalt, removeCs1, removeCs2, removeHint);
    }
    
    // ============================================================================
    // WRONG ADDRESS/FINGERPRINT TESTS - Bob tries to cancel Alice's registration intent
    // ============================================================================
    
    function testRemoveRegistrationIntentByETH_RevertWhenBobTriesToCancelAliceIntent() public {
        // First, submit Alice's registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load Bob's ETH key trying to cancel Alice's registration intent
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[7].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[7].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[7].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_eth_reverts[7].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // Bob's ETH key should not be able to cancel Alice's registration intent
        // The contract will fail at state validation because Bob's ETH address doesn't match
        // the stored intent's ETH address
        vm.expectRevert("No pending intent found for recovered ETH Address");
        registry.removeRegistrationIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveRegistrationIntentByPQ_RevertWhenBobTriesToCancelAliceIntent() public {
        // First, submit Alice's registration intent so there's a pending intent to remove
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Load Bob's PQ key trying to cancel Alice's registration intent
        string memory jsonData = vm.readFile("test/test_vectors/revert/remove_registration_intent_pq_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[6].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[6].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[6].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_registration_intent_pq_reverts[6].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_registration_intent_pq_reverts[6].pq_signature.hint"));
        
        // Bob's PQ key should not be able to cancel Alice's registration intent
        // The contract will fail at state validation because Bob's PQ fingerprint doesn't match
        // the stored intent's PQ fingerprint
        vm.expectRevert("No pending intent found for this PQ fingerprint");
        registry.removeRegistrationIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
} 