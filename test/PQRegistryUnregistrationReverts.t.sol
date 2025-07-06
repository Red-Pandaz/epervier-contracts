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

    // TODO: Implement all removeUnregistrationIntent tests
    // - testRemoveUnregistrationIntent_RevertWhenMalformedMessage()
    // - testRemoveUnregistrationIntent_RevertWhenInvalidPQSignature()
    // - testRemoveUnregistrationIntent_RevertWhenNoPendingIntent()
    // - testRemoveUnregistrationIntent_RevertWhenWrongPQNonce()
    // - testRemoveUnregistrationIntent_RevertWhenAddressMismatch()
    // - testRemoveUnregistrationIntent_RevertWhenWrongDomainSeparator()
    // - testRemoveUnregistrationIntent_RevertWhenWrongPQSigner()
    // - testRemoveUnregistrationIntent_RevertWhenETHAddressMismatch()

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