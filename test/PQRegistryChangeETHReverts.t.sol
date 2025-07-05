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
} 