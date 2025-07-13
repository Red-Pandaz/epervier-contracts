// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/PQRegistry.sol";
import "../src/PQERC721.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";

contract DeployProduction is Script {
    PQRegistry public registry;
    PQERC721 public nftContract;
    ZKNOX_epervier public epervierVerifier;
    MessageParserContract public messageParser;
    MessageValidationContract public messageValidation;
    SignatureExtractorContract public signatureExtractor;
    AddressUtilsContract public addressUtils;
    RegistrationLogicContract public registrationLogic;
    UnregistrationLogicContract public unregistrationLogic;
    ChangeAddressLogicContract public changeAddressLogic;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        console.log("=== DEPLOYING PRODUCTION CONTRACTS ===");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("");

        // 1. Deploy Epervier verifier
        console.log("1. Deploying Epervier verifier...");
        epervierVerifier = new ZKNOX_epervier();
        console.log("Epervier verifier deployed at:", address(epervierVerifier));

        // 2. Deploy utility contracts
        console.log("2. Deploying utility contracts...");
        messageParser = new MessageParserContract();
        messageValidation = new MessageValidationContract();
        signatureExtractor = new SignatureExtractorContract();
        addressUtils = new AddressUtilsContract();
        registrationLogic = new RegistrationLogicContract();
        unregistrationLogic = new UnregistrationLogicContract();
        changeAddressLogic = new ChangeAddressLogicContract();

        console.log("MessageParser deployed at:", address(messageParser));
        console.log("MessageValidation deployed at:", address(messageValidation));
        console.log("SignatureExtractor deployed at:", address(signatureExtractor));
        console.log("AddressUtils deployed at:", address(addressUtils));
        console.log("RegistrationLogic deployed at:", address(registrationLogic));
        console.log("UnregistrationLogic deployed at:", address(unregistrationLogic));
        console.log("ChangeAddressLogic deployed at:", address(changeAddressLogic));

        // 3. Deploy PQRegistry with dynamic domain separator
        console.log("3. Deploying PQRegistry...");
        registry = new PQRegistry(
            address(epervierVerifier),
            address(messageParser),
            address(messageValidation),
            address(signatureExtractor),
            address(addressUtils),
            address(registrationLogic),
            address(unregistrationLogic),
            address(changeAddressLogic)
        );
        console.log("PQRegistry deployed at:", address(registry));

        // 4. Deploy PQERC721 NFT contract
        console.log("4. Deploying PQERC721 NFT contract...");
        nftContract = new PQERC721(
            "Post-Quantum NFT",
            "PQNFT"
        );
        console.log("PQERC721 deployed at:", address(nftContract));

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

        vm.stopBroadcast();

        console.log("");
        console.log("=== PRODUCTION DEPLOYMENT COMPLETE ===");
        console.log("Registry address:", address(registry));
        console.log("NFT contract address:", address(nftContract));
        console.log("Domain separator:", vm.toString(registry.getDomainSeparator()));
        console.log("PQERC721 domain separator:", vm.toString(nftContract.getPQTransferDomainSeparator()));
        console.log("");
        console.log("Use these addresses for vector generation!");
    }
} 