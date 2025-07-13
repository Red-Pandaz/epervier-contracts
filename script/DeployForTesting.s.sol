// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/PQRegistryTest.sol";
import "../src/PQERC721Test.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";

contract DeployForTesting is Script {
    function run() external {
        // Use Anvil's default first account private key
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("=== DEPLOYING CONTRACTS FOR TESTING ===");
        console.log("");
        
        // 1. Deploy Epervier Verifier first
        console.log("1. Deploying ZKNOX_epervier verifier...");
        ZKNOX_epervier epervierVerifier = new ZKNOX_epervier();
        console.log("ZKNOX_epervier deployed at:", address(epervierVerifier));
        console.log("");
        
        // 2. Deploy library contracts
        console.log("2. Deploying library contracts...");
        
        MessageParserContract messageParser = new MessageParserContract();
        console.log("MessageParser deployed at:", address(messageParser));
        
        SignatureExtractorContract signatureExtractor = new SignatureExtractorContract();
        console.log("SignatureExtractor deployed at:", address(signatureExtractor));
        
        MessageValidationContract messageValidation = new MessageValidationContract();
        console.log("MessageValidation deployed at:", address(messageValidation));
        
        AddressUtilsContract addressUtils = new AddressUtilsContract();
        console.log("AddressUtils deployed at:", address(addressUtils));
        
        RegistrationLogicContract registrationLogic = new RegistrationLogicContract();
        console.log("RegistrationLogic deployed at:", address(registrationLogic));
        
        UnregistrationLogicContract unregistrationLogic = new UnregistrationLogicContract();
        console.log("UnregistrationLogic deployed at:", address(unregistrationLogic));
        
        ChangeAddressLogicContract changeAddressLogic = new ChangeAddressLogicContract();
        console.log("ChangeAddressLogic deployed at:", address(changeAddressLogic));
        console.log("");
        
        // 3. Deploy PQRegistryTest with real Epervier address
        console.log("3. Deploying PQRegistryTest with real Epervier verifier...");
        PQRegistryTest registry = new PQRegistryTest(
            address(epervierVerifier),    // REAL Epervier verifier address
            address(messageParser),
            address(messageValidation),
            address(signatureExtractor),
            address(addressUtils),
            address(registrationLogic),
            address(unregistrationLogic),
            address(changeAddressLogic)
        );
        console.log("PQRegistryTest deployed at:", address(registry));
        console.log("");
        
        // 4. Deploy PQERC721Test NFT contract
        console.log("4. Deploying PQERC721Test NFT contract...");
        PQERC721Test nftContract = new PQERC721Test(
            "Post-Quantum NFT",
            "PQNFT"
        );
        console.log("PQERC721Test deployed at:", address(nftContract));
        
        // 5. Initialize NFT contract with registry
        console.log("5. Initializing NFT contract with registry...");
        nftContract.initialize(address(registry));
        console.log("NFT contract initialized successfully");
        
        // 6. Initialize registry with NFT contract
        console.log("6. Initializing registry with NFT contract...");
        address[] memory nftContracts = new address[](1);
        nftContracts[0] = address(nftContract);
        registry.initializeNFTContracts(nftContracts);
        console.log("Registry initialized with NFT contract");
        console.log("");
        
        vm.stopBroadcast();
        
        console.log("=== DEPLOYMENT COMPLETE ===");
        console.log("RPC URL: http://localhost:8545");
        console.log("CHAIN ID: 31337");
        console.log("Domain separator:", vm.toString(registry.getDomainSeparator()));
        console.log("");
        console.log("=== CONTRACT ADDRESSES FOR TESTING ===");
        console.log("PQRegistryTest:", address(registry));
        console.log("PQERC721Test:", address(nftContract));
        console.log("ZKNOX_epervier:", address(epervierVerifier));
        console.log("");
        console.log("Update the registry address in TestRegistrationIntents.s.sol with:", address(registry));
    }
} 