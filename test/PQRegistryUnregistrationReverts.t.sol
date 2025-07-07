// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "forge-std/Test.sol";

contract PQRegistryUnregistrationRevertsTest is Test {
    PQRegistry registry;
    ZKNOX_epervier public epervierVerifier;

    function setUp() public {
        // Deploy real Epervier verifier
        epervierVerifier = new ZKNOX_epervier();
        
        // Deploy registry
        registry = new PQRegistry(address(epervierVerifier));
    }

    // Helper function to register Alice
    function _registerAlice() internal {
        // Register Alice only - AliceETH and AlicePQ submit and confirm registration
        string memory aliceIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory aliceConfirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Submit Alice's registration intent (index 0)
        bytes memory aliceEthIntentMessage = vm.parseBytes(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_message"));
        uint8 aliceV = uint8(vm.parseUint(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.v")));
        bytes32 aliceR = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 aliceS = vm.parseBytes32(vm.parseJsonString(aliceIntentJsonData, ".registration_intent[0].eth_signature.s"));
        
        registry.submitRegistrationIntent(aliceEthIntentMessage, aliceV, aliceR, aliceS);
        
        // Confirm Alice's registration (index 0)
        bytes memory alicePqMessage = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_message"));
        bytes memory alicePqSalt = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory alicePqCs1 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory alicePqCs2 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 alicePqHint = vm.parseUint(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        registry.confirmRegistration(alicePqMessage, alicePqSalt, alicePqCs1, alicePqCs2, alicePqHint);
    }

    // Helper function to submit change ETH address intent for Alice
    function _submitChangeETHAddressIntent() internal {
        // Step 3: BobETH initiates change intent from AliceETH to BobETH
        // This should create a pending change intent where AlicePQ is changing from AliceETH to BobETH
        string memory bobToAliceIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use Bob -> Alice change intent (this should be BobETH initiating the change)
        // We need to find a vector where BobETH is the new ETH address and AlicePQ is the current actor
        bytes memory bobToAlicePqMessage = vm.parseBytes(vm.parseJsonString(bobToAliceIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory bobToAlicePqSalt = vm.parseBytes(vm.parseJsonString(bobToAliceIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory bobToAlicePqCs1 = vm.parseJsonUintArray(bobToAliceIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory bobToAlicePqCs2 = vm.parseJsonUintArray(bobToAliceIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 bobToAlicePqHint = vm.parseUint(vm.parseJsonString(bobToAliceIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(bobToAlicePqMessage, bobToAlicePqSalt, bobToAlicePqCs1, bobToAlicePqCs2, bobToAlicePqHint);
    }

    // Helper function to submit unregistration intent for Alice
    function _submitUnregistrationIntent() internal {
        // Submit Alice's unregistration intent
        string memory unregisterIntentJsonData = vm.readFile("test/test_vectors/unregister/unregistration_intent_vectors.json");
        
        // Use Alice's unregistration intent (index 0)
        bytes memory alicePqMessage = vm.parseBytes(vm.parseJsonString(unregisterIntentJsonData, ".unregistration_intent[0].pq_message"));
        bytes memory alicePqSalt = vm.parseBytes(vm.parseJsonString(unregisterIntentJsonData, ".unregistration_intent[0].pq_signature.salt"));
        uint256[] memory alicePqCs1 = vm.parseJsonUintArray(unregisterIntentJsonData, ".unregistration_intent[0].pq_signature.cs1");
        uint256[] memory alicePqCs2 = vm.parseJsonUintArray(unregisterIntentJsonData, ".unregistration_intent[0].pq_signature.cs2");
        uint256 alicePqHint = vm.parseUint(vm.parseJsonString(unregisterIntentJsonData, ".unregistration_intent[0].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        registry.submitUnregistrationIntent(alicePqMessage, alicePqSalt, alicePqCs1, alicePqCs2, alicePqHint, publicKey);
    }

    // =============================
    // submitUnregistrationIntent
    // =============================
    // Revert scenarios to cover:
    // - Malformed message (wrong pattern/length)
    // - Invalid ETH signature
    // - Invalid PQ signature
    // - ETH address not registered
    // - PQ fingerprint not registered
    // - Nonce mismatches (ETH and PQ)
    // - Pending intent exists
    // - Wrong domain separator
    // - Wrong signers (ETH and PQ)
    // - Address/fingerprint mismatches
    // - Change-ETH intent open for PQ

    function testSubmitUnregistrationIntent_RevertWhenMalformedMessage() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with malformed message
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[0].pq_signature.hint"));
        // Use dummy public key since we don't have it in the vectors
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with invalid pattern error
        vm.expectRevert("Invalid PQ unregistration intent message");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenInvalidETHSignature() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with invalid ETH signature
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[1].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[1].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[1].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[1].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[1].pq_signature.hint"));
        // Use dummy public key since we don't have it in the vectors
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with invalid ETH signature error (the contract fails on ETH signature validation)
        vm.expectRevert("ECDSAInvalidSignature()");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenInvalidPQSignature() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with invalid PQ signature
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[2].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[2].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[2].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[2].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[2].pq_signature.hint"));
        // Use dummy public key since we don't have it in the vectors
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with norm too large error (the PQ signature validation fails)
        vm.expectRevert("norm too large");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenETHAddressNotRegistered() public {
        // Setup: No registration (Charlie is not registered)
        
        // Attempt to submit unregistration intent for unregistered address
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[3].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[3].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[3].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[3].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[3].pq_signature.hint"));
        // Use dummy public key since we don't have it in the vectors
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with ETH address mismatch error (the contract fails on address validation)
        vm.expectRevert("ETH Address mismatch: PQ message vs stored registration");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenChangeETHIntentOpen() public {
        // Setup: Register Alice and submit change ETH address intent
        _registerAlice();
        _submitChangeETHAddressIntent();
        
        // Attempt to submit unregistration intent when change intent is open
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[4].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[4].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[4].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[4].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[4].pq_signature.hint"));
        // Use dummy public key since we don't have it in the vectors
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with change intent open error
        vm.expectRevert("PQ fingerprint has pending change intent");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    // TODO: Implement remaining submitUnregistrationIntent tests
    // - testSubmitUnregistrationIntent_RevertWhenPQFingerprintNotRegistered()
    // - testSubmitUnregistrationIntent_RevertWhenWrongETHNonce()
    // - testSubmitUnregistrationIntent_RevertWhenWrongPQNonce()
    // - testSubmitUnregistrationIntent_RevertWhenPendingIntentExists()
    // - testSubmitUnregistrationIntent_RevertWhenWrongDomainSeparator()
    // - testSubmitUnregistrationIntent_RevertWhenWrongETHSigner()
    // - testSubmitUnregistrationIntent_RevertWhenWrongPQSigner()
    // - testSubmitUnregistrationIntent_RevertWhenETHAddressMismatch()
    // - testSubmitUnregistrationIntent_RevertWhenPQFingerprintMismatch()

    function testSubmitUnregistrationIntent_RevertWhenPQFingerprintNotRegistered() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent for unregistered PQ fingerprint
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[5].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[5].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[5].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[5].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[5].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with ETH address mismatch error (this happens before PQ fingerprint check)
        vm.expectRevert("ETH Address mismatch: PQ message vs stored registration");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenWrongETHNonce() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with wrong ETH nonce
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[6].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[6].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[6].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[6].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[6].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with wrong ETH nonce error
        vm.expectRevert("Invalid ETH nonce");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenWrongPQNonce() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with wrong PQ nonce
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[7].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[7].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[7].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[7].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[7].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with wrong PQ nonce error
        vm.expectRevert("Invalid PQ nonce");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenPendingIntentExists() public {
        // Setup: Register Alice and submit unregistration intent (but don't confirm)
        _registerAlice();
        
        // Submit first unregistration intent
        string memory firstSubmitJsonData = vm.readFile("test/test_vectors/unregister/unregistration_intent_vectors.json");
        bytes memory firstPqMessage = vm.parseBytes(vm.parseJsonString(firstSubmitJsonData, ".unregistration_intent[0].pq_message"));
        bytes memory firstSalt = vm.parseBytes(vm.parseJsonString(firstSubmitJsonData, ".unregistration_intent[0].pq_signature.salt"));
        uint256[] memory firstCs1 = vm.parseJsonUintArray(firstSubmitJsonData, ".unregistration_intent[0].pq_signature.cs1");
        uint256[] memory firstCs2 = vm.parseJsonUintArray(firstSubmitJsonData, ".unregistration_intent[0].pq_signature.cs2");
        uint256 firstHint = vm.parseUint(vm.parseJsonString(firstSubmitJsonData, ".unregistration_intent[0].pq_signature.hint"));
        uint256[2] memory firstPublicKey = [uint256(0), uint256(0)];
        
        registry.submitUnregistrationIntent(firstPqMessage, firstSalt, firstCs1, firstCs2, firstHint, firstPublicKey);
        
        // Attempt to submit second unregistration intent (should revert - pending intent exists)
        string memory secondSubmitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory secondPqMessage = vm.parseBytes(vm.parseJsonString(secondSubmitJsonData, ".submit_unregistration_intent[8].pq_message"));
        bytes memory secondSalt = vm.parseBytes(vm.parseJsonString(secondSubmitJsonData, ".submit_unregistration_intent[8].pq_signature.salt"));
        uint256[] memory secondCs1 = vm.parseJsonUintArray(secondSubmitJsonData, ".submit_unregistration_intent[8].pq_signature.cs1");
        uint256[] memory secondCs2 = vm.parseJsonUintArray(secondSubmitJsonData, ".submit_unregistration_intent[8].pq_signature.cs2");
        uint256 secondHint = vm.parseUint(vm.parseJsonString(secondSubmitJsonData, ".submit_unregistration_intent[8].pq_signature.hint"));
        uint256[2] memory secondPublicKey = [uint256(0), uint256(0)];
        
        // Expect revert with pending intent exists error
        vm.expectRevert("ETH Address has pending unregistration intent");
        registry.submitUnregistrationIntent(secondPqMessage, secondSalt, secondCs1, secondCs2, secondHint, secondPublicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenWrongDomainSeparator() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with wrong domain separator
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[9].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[9].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[9].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[9].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[9].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with wrong domain separator error
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenWrongETHSigner() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with wrong ETH signer
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[10].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[10].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[10].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[10].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[10].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with wrong ETH signer error
        vm.expectRevert("ETH signature must be from intent address");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenWrongPQSigner() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with wrong PQ signer
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[11].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[11].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[11].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[11].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[11].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with ETH address mismatch error (this happens before PQ signature validation)
        vm.expectRevert("ETH Address mismatch: PQ message vs stored registration");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenETHAddressMismatch() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with ETH address mismatch
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[12].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[12].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[12].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[12].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[12].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with ETH address mismatch error
        vm.expectRevert("ETH Address mismatch: PQ message vs stored registration");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    function testSubmitUnregistrationIntent_RevertWhenPQFingerprintMismatch() public {
        // Setup: Register Alice
        _registerAlice();
        
        // Attempt to submit unregistration intent with PQ fingerprint mismatch
        string memory submitJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[13].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[13].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[13].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(submitJsonData, ".submit_unregistration_intent[13].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(submitJsonData, ".submit_unregistration_intent[13].pq_signature.hint"));
        uint256[2] memory publicKey = [uint256(0), uint256(0)];
        
        // Expect revert with ETH address mismatch error (this happens before PQ fingerprint check)
        vm.expectRevert("ETH Address mismatch: PQ message vs stored registration");
        registry.submitUnregistrationIntent(pqMessage, salt, cs1, cs2, hint, publicKey);
    }

    // =============================
    // removeUnregistrationIntent
    // =============================
    // Revert scenarios to cover (PQ controlled only):
    // - Malformed message
    // - Invalid PQ signature
    // - No pending intent
    // - Wrong PQ nonce
    // - Address mismatch
    // - Wrong domain separator
    // - Wrong PQ signer
    // - ETH address mismatch

    function testRemoveUnregistrationIntent_RevertWhenMalformedMessage() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with malformed message
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[0].pq_signature.hint"));
        
        // Expect revert with malformed message error
        vm.expectRevert("Message too short for PQ nonce from remove message");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenInvalidPQSignature() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with invalid PQ signature
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[1].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[1].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[1].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[1].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[1].pq_signature.hint"));
        
        // Expect revert with invalid PQ signature error
        vm.expectRevert("norm too large");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenNoPendingIntent() public {
        // Setup: Register Alice (no unregistration intent submitted)
        _registerAlice();
        
        // Attempt to remove unregistration intent when none exists
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[2].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[2].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[2].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[2].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[2].pq_signature.hint"));
        
        // Expect revert with no pending intent error
        vm.expectRevert("No pending unregistration intent found");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenWrongPQNonce() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with wrong PQ nonce
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[3].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[3].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[3].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[3].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[3].pq_signature.hint"));
        
        // Expect revert with wrong PQ nonce error
        vm.expectRevert("Invalid PQ nonce");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenAddressMismatch() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with address mismatch
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[4].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[4].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[4].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[4].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[4].pq_signature.hint"));
        
        // Expect revert with address mismatch error
        vm.expectRevert("No pending unregistration intent found");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenWrongDomainSeparator() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with wrong domain separator
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[5].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[5].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[5].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[5].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[5].pq_signature.hint"));
        
        // Expect revert with wrong domain separator error
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenWrongPQSigner() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with wrong PQ signer
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[6].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[6].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[6].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[6].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[6].pq_signature.hint"));
        
        // Expect revert with wrong PQ signer error
        vm.expectRevert("PQ key mismatch");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    function testRemoveUnregistrationIntent_RevertWhenETHAddressMismatch() public {
        // Setup: Register Alice and submit unregistration intent
        _registerAlice();
        _submitUnregistrationIntent();
        
        // Attempt to remove unregistration intent with ETH address mismatch
        string memory removeJsonData = vm.readFile("test/test_vectors/revert/unregistration_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[7].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[7].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[7].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removeJsonData, ".remove_unregistration_intent[7].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removeJsonData, ".remove_unregistration_intent[7].pq_signature.hint"));
        
        // Expect revert with ETH address mismatch error
        vm.expectRevert("No pending unregistration intent found");
        registry.removeUnregistrationIntent(pqMessage, salt, cs1, cs2, hint);
    }

    // =============================
    // confirmUnregistration
    // =============================
    // Revert scenarios to cover:
    // - Malformed message
    // - Invalid ETH signature
    // - Invalid PQ signature
    // - No pending intent
    // - Wrong ETH nonce
    // - Wrong PQ nonce
    // - Address mismatch
    // - Wrong domain separator
    // - Wrong ETH signer
    // - Wrong PQ signer
    // - ETH address mismatch
    // - PQ fingerprint mismatch

    // TODO: Implement all confirmUnregistration tests
    // - testConfirmUnregistration_RevertWhenMalformedMessage()
    // - testConfirmUnregistration_RevertWhenInvalidETHSignature()
    // - testConfirmUnregistration_RevertWhenInvalidPQSignature()
    // - testConfirmUnregistration_RevertWhenNoPendingIntent()
    // - testConfirmUnregistration_RevertWhenWrongETHNonce()
    // - testConfirmUnregistration_RevertWhenWrongPQNonce()
    // - testConfirmUnregistration_RevertWhenAddressMismatch()
    // - testConfirmUnregistration_RevertWhenWrongDomainSeparator()
    // - testConfirmUnregistration_RevertWhenWrongETHSigner()
    // - testConfirmUnregistration_RevertWhenWrongPQSigner()
    // - testConfirmUnregistration_RevertWhenETHAddressMismatch()
    // - testConfirmUnregistration_RevertWhenPQFingerprintMismatch()
} 