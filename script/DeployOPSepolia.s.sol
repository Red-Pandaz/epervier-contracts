// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/PQRegistry.sol";
import "../src/PQERC721.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";

contract DeployOPSepolia is Script {
    function run() external {
        // Get deployment parameters from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address epervierVerifier = 0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B; // OP Sepolia Epervier contract
        
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
        
        // Deploy the registry first
        PQRegistry registry = new PQRegistry(
            epervierVerifier,
            address(messageParser),
            address(messageValidation),
            address(signatureExtractor),
            address(addressUtils),
            address(registrationLogic),
            address(unregistrationLogic),
            address(changeAddressLogic)
        );
        console.log("PQRegistry deployed at:", address(registry));
        
        console.log("Deploying PQERC721 contract...");
        PQERC721 nft = new PQERC721("PQ NFT", "PQNFT");
        console.log("PQERC721 deployed at:", address(nft));
        
        console.log("Initializing contracts with each other...");
        
        // Initialize the NFT contract with the registry
        nft.initialize(address(registry));
        console.log("NFT contract initialized with registry");
        
        // Initialize the registry with the NFT contract
        address[] memory nftContracts = new address[](1);
        nftContracts[0] = address(nft);
        registry.initializeNFTContracts(nftContracts);
        console.log("Registry initialized with NFT contract");
        
        vm.stopBroadcast();
        
        console.log("");
        console.log("Deployment Summary:");
        console.log("MessageParser:", address(messageParser));
        console.log("SignatureExtractor:", address(signatureExtractor));
        console.log("MessageValidation:", address(messageValidation));
        console.log("AddressUtils:", address(addressUtils));
        console.log("PQRegistry:", address(registry));
        console.log("PQERC721:", address(nft));
        console.log("EpervierVerifier:", epervierVerifier);
        
        // Deployment complete - addresses will be shown in forge output
    }
} 