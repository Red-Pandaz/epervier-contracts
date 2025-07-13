// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/PQRegistryTest.sol";

contract SubmitIntentsFresh is Script {
    function run() external {
        // Use Anvil's default first account private key for Alice
        uint256 alicePrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        // Use Anvil's second account private key for Bob
        uint256 bobPrivateKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        // Use Anvil's third account private key for Charlie
        uint256 charliePrivateKey = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
        
        // Load test vectors
        string memory intentVectors = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        
        // Parse intent data
        string memory alicePath = string.concat(".registration_intent[0]");
        string memory bobPath = string.concat(".registration_intent[1]");
        string memory charliePath = string.concat(".registration_intent[2]");

        bytes memory aliceEthMessage = vm.parseJsonBytes(intentVectors, string.concat(alicePath, ".eth_message"));
        uint8 aliceV = uint8(vm.parseJsonUint(intentVectors, string.concat(alicePath, ".eth_signature.v")));
        bytes32 aliceR = vm.parseJsonBytes32(intentVectors, string.concat(alicePath, ".eth_signature.r"));
        bytes32 aliceS = vm.parseJsonBytes32(intentVectors, string.concat(alicePath, ".eth_signature.s"));

        bytes memory bobEthMessage = vm.parseJsonBytes(intentVectors, string.concat(bobPath, ".eth_message"));
        uint8 bobV = uint8(vm.parseJsonUint(intentVectors, string.concat(bobPath, ".eth_signature.v")));
        bytes32 bobR = vm.parseJsonBytes32(intentVectors, string.concat(bobPath, ".eth_signature.r"));
        bytes32 bobS = vm.parseJsonBytes32(intentVectors, string.concat(bobPath, ".eth_signature.s"));

        bytes memory charlieEthMessage = vm.parseJsonBytes(intentVectors, string.concat(charliePath, ".eth_message"));
        uint8 charlieV = uint8(vm.parseJsonUint(intentVectors, string.concat(charliePath, ".eth_signature.v")));
        bytes32 charlieR = vm.parseJsonBytes32(intentVectors, string.concat(charliePath, ".eth_signature.r"));
        bytes32 charlieS = vm.parseJsonBytes32(intentVectors, string.concat(charliePath, ".eth_signature.s"));

        // Submit to the contract
        PQRegistryTest registry = PQRegistryTest(0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6);
        
        // Submit Alice's intent
        vm.startBroadcast(alicePrivateKey);
        console.log("Submitting Alice's registration intent...");
        try registry.submitRegistrationIntent(aliceEthMessage, aliceV, aliceR, aliceS) {
            console.log("SUCCESS: Alice intent submitted");
        } catch Error(string memory reason) {
            console.log("FAIL: Alice intent failed:", reason);
        } catch {
            console.log("FAIL: Alice intent failed with unknown error");
        }
        vm.stopBroadcast();

        // Submit Bob's intent
        vm.startBroadcast(bobPrivateKey);
        console.log("Submitting Bob's registration intent...");
        try registry.submitRegistrationIntent(bobEthMessage, bobV, bobR, bobS) {
            console.log("SUCCESS: Bob intent submitted");
        } catch Error(string memory reason) {
            console.log("FAIL: Bob intent failed:", reason);
        } catch {
            console.log("FAIL: Bob intent failed with unknown error");
        }
        vm.stopBroadcast();

        // Submit Charlie's intent
        vm.startBroadcast(charliePrivateKey);
        console.log("Submitting Charlie's registration intent...");
        try registry.submitRegistrationIntent(charlieEthMessage, charlieV, charlieR, charlieS) {
            console.log("SUCCESS: Charlie intent submitted");
        } catch Error(string memory reason) {
            console.log("FAIL: Charlie intent failed:", reason);
        } catch {
            console.log("FAIL: Charlie intent failed with unknown error");
        }
        vm.stopBroadcast();
        
        console.log("");
        console.log("=== ALL INTENTS SUBMITTED ===");
    }
    
    function submitIntent(bytes memory ethMessage, uint8 v, bytes32 r, bytes32 s, PQRegistryTest registry) internal {
        try registry.submitRegistrationIntent(ethMessage, v, r, s) {
            console.log("SUCCESS: intent submitted");
        } catch Error(string memory reason) {
            console.log("FAIL: intent failed:", reason);
        } catch {
            console.log("FAIL: intent failed with unknown error");
        }
    }
} 