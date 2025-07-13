// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/PQRegistry.sol";

contract TestRegistrationConfirmations is Script {
    PQRegistry public registry;

    function setUp() public {
        // Use the deployed PQRegistry address from the latest deployment
        registry = PQRegistry(0x1291Be112d480055DaFd8a610b7d1e203891C274);
    }

    function run() external {
        // Set registry address (update if needed)
        // registry = PQRegistryTest(0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6);
        console.log("=== TESTING REGISTRATION CONFIRMATIONS ===");
        console.log("Registry address:", address(registry));
        console.log("");
        
        // Alice's private key (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
        uint256 alicePrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        // Bob's private key (0x70997970C51812dc3A010C7d01b50e0d17dc79C8)
        uint256 bobPrivateKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        
        // Charlie's private key (0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC)
        uint256 charliePrivateKey = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
        
        testConfirmation(0, "Alice", alicePrivateKey);
        testConfirmation(1, "Bob", bobPrivateKey);
        testConfirmation(2, "Charlie", charliePrivateKey);
    }

    function testConfirmation(uint256 idx, string memory name, uint256 privateKey) internal {
        string memory jsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        string memory prefix = string.concat(".registration_confirmation[", vm.toString(idx), "]");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(prefix, ".pq_message")));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, string.concat(prefix, ".pq_signature.salt")));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, string.concat(prefix, ".pq_signature.cs1"));
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, string.concat(prefix, ".pq_signature.cs2"));
        uint256 hint = vm.parseJsonUint(jsonData, string.concat(prefix, ".pq_signature.hint"));
        
        vm.startBroadcast(privateKey);
        try registry.confirmRegistration(pqMessage, salt, cs1, cs2, hint) {
            console.log(string.concat(name, " registration confirmation submitted successfully"));
        } catch Error(string memory reason) {
            console.log(string.concat(name, " registration confirmation failed: "), reason);
        } catch {
            console.log(string.concat(name, " registration confirmation failed with unknown error"));
        }
        vm.stopBroadcast();
        console.log("");
    }
} 