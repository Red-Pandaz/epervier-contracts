// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/PQRegistryTest.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";

contract DeployPQRegistryTest is Script {
    function run() external {
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("Deploying library contracts...");
        
        // Deploy the 4 library contracts first
        console.log("Deploying MessageParser contract...");
        MessageParserContract messageParser = new MessageParserContract();
        console.log("MessageParser deployed at:", address(messageParser));
        
        console.log("Deploying SignatureExtractor contract...");
        SignatureExtractorContract signatureExtractor = new SignatureExtractorContract();
        console.log("SignatureExtractor deployed at:", address(signatureExtractor));
        
        console.log("Deploying MessageValidation contract...");
        MessageValidationContract messageValidation = new MessageValidationContract();
        console.log("MessageValidation deployed at:", address(messageValidation));
        
        console.log("Deploying AddressUtils contract...");
        AddressUtilsContract addressUtils = new AddressUtilsContract();
        console.log("AddressUtils deployed at:", address(addressUtils));
        
        console.log("Deploying RegistrationLogic contract...");
        RegistrationLogicContract registrationLogic = new RegistrationLogicContract();
        console.log("RegistrationLogic deployed at:", address(registrationLogic));
        
        console.log("Deploying UnregistrationLogic contract...");
        UnregistrationLogicContract unregistrationLogic = new UnregistrationLogicContract();
        console.log("UnregistrationLogic deployed at:", address(unregistrationLogic));
        
        console.log("Deploying ChangeAddressLogic contract...");
        ChangeAddressLogicContract changeAddressLogic = new ChangeAddressLogicContract();
        console.log("ChangeAddressLogic deployed at:", address(changeAddressLogic));
        
        console.log("Deploying PQRegistryTest contract...");
        PQRegistryTest registry = new PQRegistryTest(
            address(0x1234), // epervierVerifier
            address(messageParser),
            address(messageValidation),
            address(signatureExtractor),
            address(addressUtils),
            address(registrationLogic),
            address(unregistrationLogic),
            address(changeAddressLogic)
        );
        console.log("PQRegistryTest deployed at:", address(registry));
        
        vm.stopBroadcast();
        
        console.log("");
        console.log("Deployment Summary:");
        console.log("MessageParser:", address(messageParser));
        console.log("SignatureExtractor:", address(signatureExtractor));
        console.log("MessageValidation:", address(messageValidation));
        console.log("AddressUtils:", address(addressUtils));
        console.log("PQRegistryTest:", address(registry));
        console.log("EpervierVerifier:", address(0x1234));
        // Deployment complete - addresses will be shown in forge output
    }
} 