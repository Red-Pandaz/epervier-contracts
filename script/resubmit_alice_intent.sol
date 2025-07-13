// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/PQRegistryTest.sol";

contract ResubmitAliceIntent is Script {
    function run() external {
        // Use Anvil's default first account private key
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("=== RESUBMITTING ALICE'S REGISTRATION INTENT ===");
        console.log("Contract address: 0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8");
        console.log("");
        
        // Load test vectors
        string memory intentVectors = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        
        // Parse Alice's intent (first in array)
        bytes memory aliceEthMessage = vm.parseJsonBytes(intentVectors, "$.registration_intent[0].eth_message");
        uint8 aliceV = uint8(vm.parseJsonUint(intentVectors, "$.registration_intent[0].eth_signature.v"));
        bytes32 aliceR = vm.parseJsonBytes32(intentVectors, "$.registration_intent[0].eth_signature.r");
        bytes32 aliceS = vm.parseJsonBytes32(intentVectors, "$.registration_intent[0].eth_signature.s");
        
        // Submit Alice's intent
        console.log("Submitting Alice's registration intent...");
        PQRegistryTest registry = PQRegistryTest(0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8);
        registry.submitRegistrationIntent(aliceEthMessage, aliceV, aliceR, aliceS);
        console.log("Alice's intent submitted successfully");
        
        vm.stopBroadcast();
        
        console.log("");
        console.log("=== ALICE'S INTENT RESUBMITTED ===");
        console.log("Contract: 0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8");
    }
} 