// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PQRegistryTestSetup.sol";

contract PQRegistryConfirmUnregistrationRevertsTest is PQRegistryTestSetup {

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

    function testConfirmUnregistration_RevertWhenMalformedMessage() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[0].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 0);
        vm.expectRevert("Message too short for PQ hint");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenInvalidETHSignature() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[1].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 1);
        vm.expectRevert("ECDSAInvalidSignature()");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenInvalidPQSignature() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[2].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 2);
        vm.expectRevert("norm too large");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenNoPendingIntent() public {
        _registerAlice();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[3].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 3);
        vm.expectRevert("No pending unregistration intent found for ETH Address");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenWrongETHNonce() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[4].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 4);
        vm.expectRevert("Invalid ETH nonce");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenWrongPQNonce() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[5].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 5);
        vm.expectRevert("Invalid PQ nonce");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenFingerprintMismatch() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[6].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 6);
        vm.expectRevert("Fingerprint address mismatch: ETH message vs recovered PQ signature");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenWrongDomainSeparatorInPQMessage() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[7].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 7);
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenWrongDomainSeparatorInEIP712Signature() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[12].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 12);
        vm.expectRevert("ETH signature must be from registered address");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenWrongETHSigner() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[8].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 8);
        vm.expectRevert("ETH signature must be from registered address");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenWrongPQSigner() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[9].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 9);
        vm.expectRevert("Fingerprint address mismatch: ETH message vs recovered PQ signature");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    function testConfirmUnregistration_RevertWhenETHAddressMismatch() public {
        _registerAlice();
        _submitUnregistrationIntent();
        string memory jsonData = vm.readFile("test/test_vectors/revert/unregistration_confirmation_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".confirm_unregistration_intent[10].eth_message"));
        (uint8 v, bytes32 r, bytes32 s) = _parseEthSig(jsonData, 10);
        vm.expectRevert("ETH Address not registered to PQ fingerprint");
        registry.confirmUnregistration(ethMessage, v, r, s);
    }

    // Helper to parse ETH signature from JSON
    function _parseEthSig(string memory jsonData, uint256 idx) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        v = uint8(vm.parseUint(vm.parseJsonString(jsonData, string(abi.encodePacked(".confirm_unregistration_intent[", vm.toString(idx), "].eth_signature.v")))));
        r = bytes32(vm.parseUint(vm.parseJsonString(jsonData, string(abi.encodePacked(".confirm_unregistration_intent[", vm.toString(idx), "].eth_signature.r")))));
        s = bytes32(vm.parseUint(vm.parseJsonString(jsonData, string(abi.encodePacked(".confirm_unregistration_intent[", vm.toString(idx), "].eth_signature.s")))));
    }
} 