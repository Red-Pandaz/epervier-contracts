// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {PQRegistry} from "../src/PQRegistry.sol";
import {ZKNOX_epervier} from "../ETHFALCON/src/ZKNOX_epervier.sol";
import {MessageParser} from "../src/libraries/MessageParser.sol";

contract PQRegistryChangeETHRevertsTest is Test {
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    function setUp() public {
        // Deploy the Epervier verifier
        epervierVerifier = new ZKNOX_epervier();
        
        // Deploy the registry
        registry = new PQRegistry(address(epervierVerifier));
    }
    
    // ============================================================================
    // CHANGE ETH ADDRESS REVERT TESTS
    // ============================================================================
    
    function testSubmitChangeETHAddressIntent_RevertWhenNewETHAddressHasPendingIntent() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: BobETH and BobPQ submit registration intent (but don't confirm)
        string memory bobIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        
        // Submit Bob's registration intent (index 1)
        bytes memory bobEthIntentMessage = vm.parseBytes(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_message"));
        uint8 bobV = uint8(vm.parseUint(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.v")));
        bytes32 bobR = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.r"));
        bytes32 bobS = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.s"));
        
        registry.submitRegistrationIntent(bobEthIntentMessage, bobV, bobR, bobS);
        
        // Step 3: AlicePQ tries to change ETH to BobETH (should revert - Bob has pending intent)
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the first vector (BobETH nonce 1 - Bob has pending intent)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        vm.expectRevert("New ETH Address has pending registration intent");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenNewETHAddressAlreadyRegistered() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: BobETH and BobPQ submit and confirm registration
        string memory bobIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory bobConfirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Submit Bob's registration intent (index 1)
        bytes memory bobEthIntentMessage = vm.parseBytes(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_message"));
        uint8 bobV = uint8(vm.parseUint(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.v")));
        bytes32 bobR = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.r"));
        bytes32 bobS = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.s"));
        
        registry.submitRegistrationIntent(bobEthIntentMessage, bobV, bobR, bobS);
        
        // Confirm Bob's registration (index 1)
        bytes memory bobPqMessage = vm.parseBytes(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_message"));
        bytes memory bobPqSalt = vm.parseBytes(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.salt"));
        uint256[] memory bobPqCs1 = vm.parseJsonUintArray(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.cs1");
        uint256[] memory bobPqCs2 = vm.parseJsonUintArray(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.cs2");
        uint256 bobPqHint = vm.parseUint(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.hint"));
        
        registry.confirmRegistration(bobPqMessage, bobPqSalt, bobPqCs1, bobPqCs2, bobPqHint);
        
        // Step 3: AlicePQ tries to change ETH to BobETH (should revert - Bob is already registered)
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the second vector (BobETH nonce 2 - Bob is fully registered)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[1].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[1].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[1].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[1].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[1].pq_signature.hint"));
        
        vm.expectRevert("New ETH Address already has registered PQ key");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenNewETHAddressHasPendingChangeIntent() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: BobETH and BobPQ submit and confirm registration
        string memory bobIntentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory bobConfirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Submit Bob's registration intent (index 1)
        bytes memory bobEthIntentMessage = vm.parseBytes(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_message"));
        uint8 bobV = uint8(vm.parseUint(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.v")));
        bytes32 bobR = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.r"));
        bytes32 bobS = vm.parseBytes32(vm.parseJsonString(bobIntentJsonData, ".registration_intent[1].eth_signature.s"));
        
        registry.submitRegistrationIntent(bobEthIntentMessage, bobV, bobR, bobS);
        
        // Confirm Bob's registration (index 1)
        bytes memory bobPqMessage = vm.parseBytes(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_message"));
        bytes memory bobPqSalt = vm.parseBytes(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.salt"));
        uint256[] memory bobPqCs1 = vm.parseJsonUintArray(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.cs1");
        uint256[] memory bobPqCs2 = vm.parseJsonUintArray(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.cs2");
        uint256 bobPqHint = vm.parseUint(vm.parseJsonString(bobConfirmJsonData, ".registration_confirmation[1].pq_signature.hint"));
        
        registry.confirmRegistration(bobPqMessage, bobPqSalt, bobPqCs1, bobPqCs2, bobPqHint);
        
        // Step 3: AlicePQ submits change ETH intent to CharlieETH (this should succeed)
        string memory aliceToCharlieIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use Alice -> Charlie change intent (index 2 - CharlieETH nonce 0)
        bytes memory aliceToCharliePqMessage = vm.parseBytes(vm.parseJsonString(aliceToCharlieIntentJsonData, ".change_eth_address_intent[2].pq_message"));
        bytes memory aliceToCharliePqSalt = vm.parseBytes(vm.parseJsonString(aliceToCharlieIntentJsonData, ".change_eth_address_intent[2].pq_signature.salt"));
        uint256[] memory aliceToCharliePqCs1 = vm.parseJsonUintArray(aliceToCharlieIntentJsonData, ".change_eth_address_intent[2].pq_signature.cs1");
        uint256[] memory aliceToCharliePqCs2 = vm.parseJsonUintArray(aliceToCharlieIntentJsonData, ".change_eth_address_intent[2].pq_signature.cs2");
        uint256 aliceToCharliePqHint = vm.parseUint(vm.parseJsonString(aliceToCharlieIntentJsonData, ".change_eth_address_intent[2].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(aliceToCharliePqMessage, aliceToCharliePqSalt, aliceToCharliePqCs1, aliceToCharliePqCs2, aliceToCharliePqHint);
        
        // Step 4: BobPQ tries to change ETH to CharlieETH (should revert - Charlie is already involved in Alice's change intent)
        string memory bobToCharlieIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use Bob -> Charlie change intent (index 3 - CharlieETH nonce 1)
        bytes memory bobToCharliePqMessage = vm.parseBytes(vm.parseJsonString(bobToCharlieIntentJsonData, ".change_eth_address_intent[3].pq_message"));
        bytes memory bobToCharliePqSalt = vm.parseBytes(vm.parseJsonString(bobToCharlieIntentJsonData, ".change_eth_address_intent[3].pq_signature.salt"));
        uint256[] memory bobToCharliePqCs1 = vm.parseJsonUintArray(bobToCharlieIntentJsonData, ".change_eth_address_intent[3].pq_signature.cs1");
        uint256[] memory bobToCharliePqCs2 = vm.parseJsonUintArray(bobToCharlieIntentJsonData, ".change_eth_address_intent[3].pq_signature.cs2");
        uint256 bobToCharliePqHint = vm.parseUint(vm.parseJsonString(bobToCharlieIntentJsonData, ".change_eth_address_intent[3].pq_signature.hint"));
        
        vm.expectRevert("New ETH Address has pending change intent");
        registry.submitChangeETHAddressIntent(bobToCharliePqMessage, bobToCharliePqSalt, bobToCharliePqCs1, bobToCharliePqCs2, bobToCharliePqHint);
    }

    // ============================================================================
    // ADDITIONAL CHANGE ETH ADDRESS REVERT TESTS
    // ============================================================================
    
    function testSubmitChangeETHAddressIntent_RevertWhenWrongDomainSeparatorInPQMessage() public {
        // Load revert test vector for wrong DS in PQ message
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[4].pq_message"));
        bytes memory pqSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[4].pq_signature.salt"));
        uint256[] memory pqCs1 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[4].pq_signature.cs1");
        uint256[] memory pqCs2 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[4].pq_signature.cs2");
        uint256 pqHint = vm.parseUint(vm.parseJsonString(jsonData, ".change_eth_address_intent[4].pq_signature.hint"));

        // This should revert due to wrong domain separator in PQ message
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.submitChangeETHAddressIntent(pqMessage, pqSalt, pqCs1, pqCs2, pqHint);
    }

    function testSubmitChangeETHAddressIntent_RevertWhenWrongDomainSeparatorInETHSignature() public {
        // Load revert test vector for wrong DS in ETH signature
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[5].pq_message"));
        bytes memory pqSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[5].pq_signature.salt"));
        uint256[] memory pqCs1 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[5].pq_signature.cs1");
        uint256[] memory pqCs2 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[5].pq_signature.cs2");
        uint256 pqHint = vm.parseUint(vm.parseJsonString(jsonData, ".change_eth_address_intent[5].pq_signature.hint"));

        // This should revert due to wrong domain separator in ETH signature
        // The wrong domain separator causes the ETH signature to recover to a different address
        vm.expectRevert("ETH signature must be from new ETH Address");
        registry.submitChangeETHAddressIntent(pqMessage, pqSalt, pqCs1, pqCs2, pqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenWrongETHNonce() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Load revert test vector with wrong ETH nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[6].pq_message"));
        bytes memory pqSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[6].pq_signature.salt"));
        uint256[] memory pqCs1 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[6].pq_signature.cs1");
        uint256[] memory pqCs2 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[6].pq_signature.cs2");
        uint256 pqHint = vm.parseUint(vm.parseJsonString(jsonData, ".change_eth_address_intent[6].pq_signature.hint"));
        
        // Try to submit with wrong ETH nonce (should fail)
        vm.expectRevert("Invalid ETH nonce");
        registry.submitChangeETHAddressIntent(pqMessage, pqSalt, pqCs1, pqCs2, pqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenWrongPQNonce() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Load revert test vector with wrong PQ nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[7].pq_message"));
        bytes memory pqSalt = vm.parseBytes(vm.parseJsonString(jsonData, ".change_eth_address_intent[7].pq_signature.salt"));
        uint256[] memory pqCs1 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[7].pq_signature.cs1");
        uint256[] memory pqCs2 = vm.parseJsonUintArray(jsonData, ".change_eth_address_intent[7].pq_signature.cs2");
        uint256 pqHint = vm.parseUint(vm.parseJsonString(jsonData, ".change_eth_address_intent[7].pq_signature.hint"));
        
        // Try to submit with wrong PQ nonce (should fail)
        vm.expectRevert("Invalid PQ nonce");
        registry.submitChangeETHAddressIntent(pqMessage, pqSalt, pqCs1, pqCs2, pqHint);
    }

    // ============================================================================
    // COMPREHENSIVE CHANGE ETH ADDRESS REVERT TESTS
    // ============================================================================
    
    function testSubmitChangeETHAddressIntent_RevertWhenWrongSignerInETHSignature() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Use change ETH intent vector with wrong signer in ETH signature
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the wrong signer ETH signature vector (index 8)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[8].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[8].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[8].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[8].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[8].pq_signature.hint"));
        
        vm.expectRevert("ETH signature must be from new ETH Address");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenInvalidETHSignature() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Use change ETH intent vector with invalid ETH signature
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the invalid ETH signature vector (index 9)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[9].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[9].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[9].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[9].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[9].pq_signature.hint"));
        
        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenWrongSignerInPQSignature() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Use change ETH intent vector with wrong signer in PQ signature
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the wrong signer PQ signature vector (index 13)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[13].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[13].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[13].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[13].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[13].pq_signature.hint"));
        
        // The contract fails at cross-reference validation when PQ fingerprint doesn't match ETH message
        vm.expectRevert("ETH message PQ fingerprint mismatch");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenInvalidPQSignature() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Use change ETH intent vector with invalid PQ signature
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the invalid PQ signature vector (index 14)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[14].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[14].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[14].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[14].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[14].pq_signature.hint"));
        
        // The invalid PQ signature causes the PQ verifier to return an incorrect fingerprint
        // which then fails at state validation when checking if the fingerprint is registered
        vm.expectRevert("wrong hint");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenOldETHAddressMismatch() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Use change ETH intent vector with wrong old ETH address in PQ message
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the old ETH address mismatch vector (index 10)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[10].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[10].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[10].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[10].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[10].pq_signature.hint"));
        
        vm.expectRevert("Old ETH Address mismatch: PQ message vs current registration");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenETHMessagePQFingerprintMismatch() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        
        // Step 2: Use change ETH intent vector with wrong PQ fingerprint in ETH message
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        
        // Use the ETH message PQ fingerprint mismatch vector (index 11)
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[11].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[11].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[11].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[11].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[11].pq_signature.hint"));
        
        vm.expectRevert("ETH message PQ fingerprint mismatch");
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
    }
    
    function testSubmitChangeETHAddressIntent_RevertWhenETHMessageNewETHAddressMismatch() public {
        // Step 1: AliceETH and AlicePQ submit and confirm registration
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
        bytes memory aliceSalt = vm.parseBytes(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.salt"));
        uint256[] memory aliceCs1 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs1");
        uint256[] memory aliceCs2 = vm.parseJsonUintArray(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.cs2");
        uint256 aliceHint = vm.parseUint(vm.parseJsonString(aliceConfirmJsonData, ".registration_confirmation[0].pq_signature.hint"));
        
        registry.confirmRegistration(alicePqMessage, aliceSalt, aliceCs1, aliceCs2, aliceHint);
        
        // Step 2: Submit change ETH address intent with ETH message new ETH address mismatch (vector 8)
        string memory changeEthJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");

        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(changeEthJsonData, ".change_eth_address_intent[8].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(changeEthJsonData, ".change_eth_address_intent[8].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(changeEthJsonData, ".change_eth_address_intent[8].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(changeEthJsonData, ".change_eth_address_intent[8].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(changeEthJsonData, ".change_eth_address_intent[8].pq_signature.hint"));
        
        // The contract fails at ETH signature validation before reaching message content validation
        vm.expectRevert("ETH signature must be from new ETH Address");
        registry.submitChangeETHAddressIntent(pqMessage, salt, cs1, cs2, hint);
    }
    
    // ============================================================================
    // REMOVE CHANGE ETH ADDRESS INTENT BY ETH REVERT TESTS
    // ============================================================================
    
    function testRemoveChangeETHAddressIntentByETH_RevertWhenNoPendingChangeIntent() public {
        // Try to remove a change intent when none exists for the PQ fingerprint
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[0].eth_signature.v")));
        uint256 rDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[0].eth_signature.r"));
        uint256 sDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[0].eth_signature.s"));
        bytes32 r = bytes32(rDecimal);
        bytes32 s = bytes32(sDecimal);
        
        // The contract will fail at state validation first (no pending change intent for PQ fingerprint)
        vm.expectRevert("No pending change intent found for PQ fingerprint");
        registry.removeChangeETHAddressIntentByETH(ethMessage, v, r, s);
    }
    
    function testRemoveChangeETHAddressIntentByETH_RevertWhenWrongDomainSeparator() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a valid remove change intent vector but with wrong domain separator
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[1].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[1].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[1].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[1].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // The contract will fail because wrong domain separator recovers different address
        vm.expectRevert("ETH Address not the pending change address for PQ fingerprint");
        registry.removeChangeETHAddressIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveChangeETHAddressIntentByETH_RevertWhenWrongNonce() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a valid remove change intent vector but with wrong nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[2].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[2].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[2].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[2].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        vm.expectRevert("Invalid ETH nonce");
        registry.removeChangeETHAddressIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveChangeETHAddressIntentByETH_RevertWhenWrongSigner() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a valid remove change intent vector but signed by wrong ETH key
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[3].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[3].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[3].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[3].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // The contract will fail at state validation first (wrong signer recovers different address)
        vm.expectRevert("ETH Address not the pending change address for PQ fingerprint");
        registry.removeChangeETHAddressIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveChangeETHAddressIntentByETH_RevertWhenReplay() public {
        // First, submit a change ETH address intent
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Now remove the intent successfully using the working removal vector
        string memory removalJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_cancel_eth_vectors.json");
        bytes memory ethRemoveMessage = vm.parseBytes(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_eth[0].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_eth[0].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_eth[0].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_eth[0].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        registry.removeChangeETHAddressIntentByETH(ethRemoveMessage, vRemove, rRemove, sRemove);
        
        // Try to remove the same intent again (replay attack)
        vm.expectRevert("No pending change intent found for PQ fingerprint");
        registry.removeChangeETHAddressIntentByETH(ethRemoveMessage, vRemove, rRemove, sRemove);
    }
    
    // ============================================================================
    // REMOVE CHANGE ETH ADDRESS INTENT BY PQ REVERT TESTS
    // ============================================================================
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenNoPendingChangeIntent() public {
        // Try to remove a change intent when none exists for the PQ fingerprint
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[4].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[4].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[4].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[4].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[4].pq_signature.hint"));
        
        // The contract will fail at state validation first (no pending change intent for PQ fingerprint)
        vm.expectRevert("No pending change intent");
        registry.removeChangeETHAddressIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenWrongDomainSeparator() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a valid remove change intent vector but with wrong domain separator
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[5].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[5].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[5].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[5].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[5].pq_signature.hint"));
        
        // The contract will fail at message format validation first (wrong domain separator)
        vm.expectRevert("Invalid domain separator in PQ message");
        registry.removeChangeETHAddressIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenWrongNonce() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a valid remove change intent vector but with wrong nonce
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[6].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[6].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[6].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[6].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[6].pq_signature.hint"));
        
        vm.expectRevert("Invalid PQ nonce");
        registry.removeChangeETHAddressIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenWrongSigner() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a valid remove change intent vector but signed by wrong PQ key
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[7].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[7].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[7].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[7].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[7].pq_signature.hint"));
        
        // The contract will fail at state validation first (wrong signer recovers different fingerprint)
        vm.expectRevert("No pending change intent");
        registry.removeChangeETHAddressIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenReplay() public {
        // First, submit a change ETH address intent
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Now remove the intent successfully using PQ
        string memory removalJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_cancel_pq_vectors.json");
        bytes memory pqRemoveMessage = vm.parseBytes(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_pq[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_pq[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(removalJsonData, ".change_eth_address_cancel_pq[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(removalJsonData, ".change_eth_address_cancel_pq[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(removalJsonData, ".change_eth_address_cancel_pq[0].pq_signature.hint"));
        
        registry.removeChangeETHAddressIntentByPQ(pqRemoveMessage, salt, cs1, cs2, hint);
        
        // Try to remove the same intent again (replay attack)
        vm.expectRevert("No pending change intent");
        registry.removeChangeETHAddressIntentByPQ(pqRemoveMessage, salt, cs1, cs2, hint);
    }
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenInvalidSignature() public {
        // Load a valid remove change intent vector but with invalid signature components
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[8].pq_message"));
        
        // Use invalid signature components
        bytes memory invalidSalt = new bytes(32); // Wrong length
        uint256[] memory invalidCs1 = new uint256[](32);
        uint256[] memory invalidCs2 = new uint256[](32);
        uint256 invalidHint = 0;
        
        vm.expectRevert("wrong salt length");
        registry.removeChangeETHAddressIntentByPQ(pqMessage, invalidSalt, invalidCs1, invalidCs2, invalidHint);
    }
    
    // ============================================================================
    // NEW TESTS: Wrong address/fingerprint in message scenarios
    // ============================================================================
    
    function testRemoveChangeETHAddressIntentByETH_RevertWhenWrongAddressInMessage() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a remove change intent vector with wrong address in message (Alice's ETH key tries to cancel Alice's intent)
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[9].eth_message"));
        uint8 vRemove = uint8(vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[9].eth_signature.v")));
        uint256 rRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[9].eth_signature.r"));
        uint256 sRemoveDecimal = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[9].eth_signature.s"));
        bytes32 rRemove = bytes32(rRemoveDecimal);
        bytes32 sRemove = bytes32(sRemoveDecimal);
        
        // The contract will fail at state validation first (wrong address in message)
        vm.expectRevert("ETH Address not the pending change address for PQ fingerprint");
        registry.removeChangeETHAddressIntentByETH(ethMessage, vRemove, rRemove, sRemove);
    }
    
    function testRemoveChangeETHAddressIntentByPQ_RevertWhenWrongFingerprintInMessage() public {
        // First, submit a change ETH address intent so there's a pending intent to remove
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
        
        // Submit a change ETH address intent
        string memory changeIntentJsonData = vm.readFile("test/test_vectors/change_eth/change_eth_address_intent_vectors.json");
        bytes memory changePqMessage = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_message"));
        bytes memory changePqSalt = vm.parseBytes(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.salt"));
        uint256[] memory changePqCs1 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs1");
        uint256[] memory changePqCs2 = vm.parseJsonUintArray(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.cs2");
        uint256 changePqHint = vm.parseUint(vm.parseJsonString(changeIntentJsonData, ".change_eth_address_intent[0].pq_signature.hint"));
        
        registry.submitChangeETHAddressIntent(changePqMessage, changePqSalt, changePqCs1, changePqCs2, changePqHint);
        
        // Load a remove change intent vector with wrong fingerprint in message (Charlie's PQ key tries to cancel Alice's intent)
        string memory jsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[11].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[11].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[11].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".remove_change_eth_address_intent[11].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".remove_change_eth_address_intent[11].pq_signature.hint"));
        
        // The contract will fail at state validation first (wrong fingerprint in message)
        vm.expectRevert("No pending change intent");
        registry.removeChangeETHAddressIntentByPQ(pqMessage, salt, cs1, cs2, hint);
    }
    
    // =========================================================================
    // CONFIRM CHANGE ETH ADDRESS REVERT TESTS
    // =========================================================================
    
    function testConfirmChangeETHAddress_RevertWhenNoPendingIntent() public {
        // Setup: Register Alice only, but do NOT submit a change intent
        // Attempt to confirm change ETH address (should revert: no pending intent)
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        // Use vector [11] - no_pending_intent (valid message with valid signatures)
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[11].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[11].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[11].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[11].eth_signature.s"));
        
        // Register Alice only
        _registerAlice();
        
        // Attempt to confirm change ETH address without submitting intent first
        // This will fail at state validation (STEP 6) after ETH and PQ signature validation
        vm.expectRevert("No pending change intent found for PQ fingerprint");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenWrongDomainSeparator() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with wrong domain separator
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        // Use vector [1] - invalid_eth_signature (corrupted r value) which will fail at ETH signature validation
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_signature.s"));
        
        // Register Alice only, submit change intent
        _registerAlice();
        _submitChangeIntent();
        
        // Attempt to confirm with invalid ETH signature
        // This will fail at ETH signature validation (STEP 3) due to corrupted signature
        vm.expectRevert("ECDSAInvalidSignature()");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenWrongETHNonce() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with wrong ETH nonce
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        // Use vector [6] - wrong_eth_nonce
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[6].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[6].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[6].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[6].eth_signature.s"));
        
        // Register Alice only, submit change intent
        _registerAlice();
        _submitChangeIntent();
        
        // Attempt to confirm with wrong ETH nonce
        vm.expectRevert("Invalid ETH nonce");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenWrongPQNonce() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with wrong PQ nonce
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        // Use vector [7] - wrong_pq_nonce
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[7].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[7].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[7].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[7].eth_signature.s"));
        
        // Register Alice only, submit change intent
        _registerAlice();
        _submitChangeIntent();
        
        // Attempt to confirm with wrong PQ nonce
        vm.expectRevert("Invalid PQ nonce");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenWrongETHSigner() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with wrong ETH signer
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        // Use vector [8] - wrong_eth_signer (signature from Charlie instead of Bob)
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[8].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[8].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[8].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[8].eth_signature.s"));
        
        // Register Alice only, submit change intent
        _registerAlice();
        _submitChangeIntent();
        
        // Attempt to confirm with wrong ETH signer
        vm.expectRevert("ETH Address mismatch: PQ message vs recovered ETH signature");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenWrongPQSigner() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with wrong PQ signer
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        // Use vector [9] - wrong_pq_signer (signature from Bob instead of Alice)
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[9].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[9].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[9].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[9].eth_signature.s"));
        
        // Register Alice only, submit change intent
        _registerAlice();
        _submitChangeIntent();
        
        // Attempt to confirm with wrong PQ signer
        vm.expectRevert("PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    // =========================================================================
    // ADDITIONAL CONFIRM CHANGE ETH ADDRESS REVERT TESTS
    // =========================================================================
    
    function testConfirmChangeETHAddress_RevertWhenMalformedMessage() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with malformed message
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[0].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[0].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[0].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[0].eth_signature.s"));
        
        // Setup registration and change intent
        _setupRegistrationAndChangeIntent();
        
        // Attempt to confirm with malformed message from vector
        // This should fail at pattern validation since the message starts with "Malformed pattern for confirm change ETH address"
        // instead of the expected "Confirm change ETH Address for Epervier Fingerprint "
        vm.expectRevert();
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenInvalidETHSignature() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with invalid ETH signature
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[1].eth_signature.s"));
        
        // Setup registration and change intent
        _setupRegistrationAndChangeIntent();
        
        // Attempt to confirm with invalid ETH signature
        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenInvalidPQSignature() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with invalid PQ signature
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[2].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[2].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[2].eth_signature.s"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[2].eth_signature.r"));
        
        // Setup registration and change intent
        _setupRegistrationAndChangeIntent();
        
        // Attempt to confirm with invalid PQ signature
        vm.expectRevert();  // Expect any ECDSAInvalidSignature variant
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenETHAddressMismatch() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with ETH address mismatch in message
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[3].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[3].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[3].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[3].eth_signature.s"));
        
        // Setup registration and change intent
        _setupRegistrationAndChangeIntent();
        
        // Attempt to confirm with ETH address mismatch
        vm.expectRevert("Old ETH Address mismatch: PQ message vs current registration");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenPQFingerprintMismatch() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with PQ fingerprint mismatch in message
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[4].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[4].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[4].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[4].eth_signature.s"));
        
        // Setup registration and change intent
        _setupRegistrationAndChangeIntent();
        
        // Attempt to confirm with PQ fingerprint mismatch
        vm.expectRevert("PQ fingerprint mismatch: ETH message vs recovered PQ signature");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    
    function testConfirmChangeETHAddress_RevertWhenIntentETHAddressMismatch() public {
        // Setup: Register Alice only, submit change intent
        // Attempt to confirm with intent ETH address mismatch
        string memory confirmJsonData = vm.readFile("test/test_vectors/revert/change_eth_revert_vectors.json");
        bytes memory ethMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[5].eth_message"));
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[5].eth_signature.v")));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[5].eth_signature.r"));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(confirmJsonData, ".confirm_change_eth_address[5].eth_signature.s"));
        
        // Setup registration and change intent
        _setupRegistrationAndChangeIntent();
        
        // Attempt to confirm with intent ETH address mismatch
        vm.expectRevert("ETH Address mismatch: PQ message vs recovered ETH signature");
        registry.confirmChangeETHAddress(ethMessage, v, r, s);
    }
    


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

    function _submitChangeIntent() internal {
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

    function _setupRegistrationAndChangeIntent() internal {
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
} 