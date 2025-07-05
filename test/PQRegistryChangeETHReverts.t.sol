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
} 