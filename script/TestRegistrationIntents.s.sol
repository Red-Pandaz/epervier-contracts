// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/PQRegistry.sol";

contract TestRegistrationIntents is Script {
    // Contract addresses (will be set after deployment)
    PQRegistry public registry;
    
    // Test addresses from actor config
    address public alice;
    address public bob;
    address public charlie;
    address public danielle;
    
    // Test fingerprints from actor config
    address public aliceFingerprint;
    address public bobFingerprint;
    address public charlieFingerprint;
    address public danielleFingerprint;
    
    function run() external {
        // Load actor config
        loadActorConfig();
        
        // Set registry address (update this after deployment)
        registry = PQRegistry(0x1291Be112d480055DaFd8a610b7d1e203891C274); // Updated address from deployment
        
        console.log("=== TESTING REGISTRATION INTENTS ===");
        console.log("Registry address:", address(registry));
        console.log("Domain separator:", vm.toString(registry.getDomainSeparator()));
        console.log("");
        
        // Start broadcasting transactions
        vm.startBroadcast();
        
        // Test registration intents
        testAliceRegistrationIntent();
        testBobRegistrationIntent();
        testCharlieRegistrationIntent();
        
        // Stop broadcasting
        vm.stopBroadcast();
    }
    
    function loadActorConfig() internal {
        console.log("=== LOADING ACTOR CONFIG ===");
        
        // Load actor config
        string memory jsonData = vm.readFile("test/test_keys/actors_config.json");
        
        // Parse addresses
        alice = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.alice.eth_address"));
        bob = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.bob.eth_address"));
        charlie = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.charlie.eth_address"));
        danielle = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.danielle.eth_address"));
        
        // Parse fingerprints
        aliceFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.alice.pq_fingerprint"));
        bobFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.bob.pq_fingerprint"));
        charlieFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.charlie.pq_fingerprint"));
        danielleFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.danielle.pq_fingerprint"));
        
        console.log("Alice:", alice);
        console.log("Bob:", bob);
        console.log("Charlie:", charlie);
        console.log("Alice Fingerprint:", aliceFingerprint);
        console.log("Bob Fingerprint:", bobFingerprint);
        console.log("Charlie Fingerprint:", charlieFingerprint);
        console.log("");
    }
    
    function testAliceRegistrationIntent() internal {
        console.log("=== TESTING ALICE'S REGISTRATION INTENT ===");
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[0].eth_message"));
        uint8 v = uint8(vm.parseJsonUint(jsonData, ".registration_intent[0].eth_signature.v"));
        bytes32 r = bytes32(vm.parseJsonUint(jsonData, ".registration_intent[0].eth_signature.r"));
        bytes32 s = bytes32(vm.parseJsonUint(jsonData, ".registration_intent[0].eth_signature.s"));
        try registry.submitRegistrationIntent(ethIntentMessage, v, r, s) {
            console.log("Alice registration intent submitted successfully");
        } catch Error(string memory reason) {
            console.log("Alice registration intent failed:", reason);
        } catch {
            console.log("Alice registration intent failed with unknown error");
        }
        console.log("");
    }
    function testBobRegistrationIntent() internal {
        console.log("=== TESTING BOB'S REGISTRATION INTENT ===");
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[1].eth_message"));
        uint8 v = uint8(vm.parseJsonUint(jsonData, ".registration_intent[1].eth_signature.v"));
        bytes32 r = bytes32(vm.parseJsonUint(jsonData, ".registration_intent[1].eth_signature.r"));
        bytes32 s = bytes32(vm.parseJsonUint(jsonData, ".registration_intent[1].eth_signature.s"));
        try registry.submitRegistrationIntent(ethIntentMessage, v, r, s) {
            console.log("Bob registration intent submitted successfully");
        } catch Error(string memory reason) {
            console.log("Bob registration intent failed:", reason);
        } catch {
            console.log("Bob registration intent failed with unknown error");
        }
        console.log("");
    }
    function testCharlieRegistrationIntent() internal {
        console.log("=== TESTING CHARLIE'S REGISTRATION INTENT ===");
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".registration_intent[2].eth_message"));
        uint8 v = uint8(vm.parseJsonUint(jsonData, ".registration_intent[2].eth_signature.v"));
        bytes32 r = bytes32(vm.parseJsonUint(jsonData, ".registration_intent[2].eth_signature.r"));
        bytes32 s = bytes32(vm.parseJsonUint(jsonData, ".registration_intent[2].eth_signature.s"));
        try registry.submitRegistrationIntent(ethIntentMessage, v, r, s) {
            console.log("Charlie registration intent submitted successfully");
        } catch Error(string memory reason) {
            console.log("Charlie registration intent failed:", reason);
        } catch {
            console.log("Charlie registration intent failed with unknown error");
        }
        console.log("");
    }
} 