// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/PQRegistry.sol";
import "../src/PQERC721.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";

contract DeployProductionContracts is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        console.log("Deploying production contracts...");

        // Deploy the Epervier verifier first
        console.log("Deploying Epervier verifier...");
        ZKNOX_epervier epervierVerifier = new ZKNOX_epervier();
        console.log("Epervier verifier deployed at:", address(epervierVerifier));

        // Deploy the utility contracts
        console.log("Deploying utility contracts...");
        AddressUtilsContract addressUtils = new AddressUtilsContract();
        MessageParserContract messageParser = new MessageParserContract();
        ChangeAddressLogicContract changeAddressLogic = new ChangeAddressLogicContract();
        UnregistrationLogicContract unregistrationLogic = new UnregistrationLogicContract();
        RegistrationLogicContract registrationLogic = new RegistrationLogicContract();

        console.log("AddressUtils deployed at:", address(addressUtils));
        console.log("MessageParser deployed at:", address(messageParser));
        console.log("ChangeAddressLogic deployed at:", address(changeAddressLogic));
        console.log("UnregistrationLogic deployed at:", address(unregistrationLogic));
        console.log("RegistrationLogic deployed at:", address(registrationLogic));

        // Deploy the main PQRegistry contract
        console.log("Deploying PQRegistry...");
        PQRegistry pqRegistry = new PQRegistry(
            address(epervierVerifier),
            address(messageParser),
            address(messageParser), // messageValidation (using messageParser for now)
            address(messageParser), // signatureExtractor (using messageParser for now)
            address(addressUtils),
            address(registrationLogic),
            address(unregistrationLogic),
            address(changeAddressLogic)
        );
        console.log("PQRegistry deployed at:", address(pqRegistry));

        // Deploy the PQERC721 contract
        console.log("Deploying PQERC721...");
        PQERC721 pqERC721 = new PQERC721("PQ Token", "PQT");
        console.log("PQERC721 deployed at:", address(pqERC721));

        // Register the PQERC721 contract with the registry
        console.log("Registering PQERC721 with PQRegistry...");
        pqRegistry.registerNFTContract(address(pqERC721));
        console.log("PQERC721 registered successfully");

        vm.stopBroadcast();

        console.log("\n=== PRODUCTION DEPLOYMENT SUMMARY ===");
        console.log("Epervier Verifier:", address(epervierVerifier));
        console.log("PQRegistry:", address(pqRegistry));
        console.log("PQERC721:", address(pqERC721));
        console.log("AddressUtils:", address(addressUtils));
        console.log("MessageParser:", address(messageParser));
        console.log("ChangeAddressLogic:", address(changeAddressLogic));
        console.log("UnregistrationLogic:", address(unregistrationLogic));
        console.log("RegistrationLogic:", address(registrationLogic));
        console.log("=====================================");
    }
} 