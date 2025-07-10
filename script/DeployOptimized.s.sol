// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";
import "../src/PQRegistry.sol";
import "../src/PQERC721.sol";

contract DeployOptimizedScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying from address:", deployer);
        console.log("Balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy library contracts first
        console.log("Deploying MessageParserContract...");
        MessageParserContract messageParser = new MessageParserContract();
        console.log("MessageParserContract deployed at:", address(messageParser));
        
        console.log("Deploying MessageValidationContract...");
        MessageValidationContract messageValidation = new MessageValidationContract();
        console.log("MessageValidationContract deployed at:", address(messageValidation));
        
        console.log("Deploying SignatureExtractorContract...");
        SignatureExtractorContract signatureExtractor = new SignatureExtractorContract();
        console.log("SignatureExtractorContract deployed at:", address(signatureExtractor));
        
        console.log("Deploying AddressUtilsContract...");
        AddressUtilsContract addressUtils = new AddressUtilsContract();
        console.log("AddressUtilsContract deployed at:", address(addressUtils));
        
        // Deploy Epervier verifier (this should be the actual deployed address)
        address epervierVerifier = vm.envAddress("EPERVIER_VERIFIER_ADDRESS");
        console.log("Using Epervier verifier at:", epervierVerifier);
        
        console.log("Deploying RegistrationLogic contract...");
        RegistrationLogicContract registrationLogic = new RegistrationLogicContract();
        console.log("RegistrationLogic deployed at:", address(registrationLogic));
        
        console.log("Deploying UnregistrationLogic contract...");
        UnregistrationLogicContract unregistrationLogic = new UnregistrationLogicContract();
        console.log("UnregistrationLogic deployed at:", address(unregistrationLogic));
        
        console.log("Deploying ChangeAddressLogic contract...");
        ChangeAddressLogicContract changeAddressLogic = new ChangeAddressLogicContract();
        console.log("ChangeAddressLogic deployed at:", address(changeAddressLogic));
        
        // Deploy PQRegistry with library contracts
        console.log("Deploying PQRegistry...");
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
        
        // Deploy PQERC721
        console.log("Deploying PQERC721...");
        PQERC721 nft = new PQERC721("PQ Token", "PQT");
        console.log("PQERC721 deployed at:", address(nft));
        
        // Initialize the contracts
        console.log("Initializing contracts...");
        
        // Register NFT contract with registry
        address[] memory nftContracts = new address[](1);
        nftContracts[0] = address(nft);
        registry.initializeNFTContracts(nftContracts);
        
        // Initialize NFT contract with registry
        nft.initialize(address(registry));
        
        vm.stopBroadcast();
        
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log("MessageParserContract:", address(messageParser));
        console.log("MessageValidationContract:", address(messageValidation));
        console.log("SignatureExtractorContract:", address(signatureExtractor));
        console.log("AddressUtilsContract:", address(addressUtils));
        console.log("PQRegistry:", address(registry));
        console.log("PQERC721:", address(nft));
        console.log("EpervierVerifier:", epervierVerifier);
        console.log("===========================");
    }
} 