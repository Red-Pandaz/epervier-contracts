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
    
} 