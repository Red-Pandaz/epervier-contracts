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

contract DeployAndTestDevnet is Script {
    // Deployed contract addresses
    ZKNOX_epervier public epervierVerifier;
    PQRegistryTest public registry;
    PQERC721Test public nftContract;
    MessageParserContract public messageParser;
    SignatureExtractorContract public signatureExtractor;
    MessageValidationContract public messageValidation;
    AddressUtilsContract public addressUtils;
    RegistrationLogicContract public registrationLogic;
    UnregistrationLogicContract public unregistrationLogic;
    ChangeAddressLogicContract public changeAddressLogic;
    
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
        // Use Anvil's default first account private key
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("=== DEPLOYING COMPLETE PQ SYSTEM TO LOCAL DEVNET ===");
        console.log("");
        
        // 1. Deploy Epervier Verifier first
        console.log("1. Deploying ZKNOX_epervier verifier...");
        epervierVerifier = new ZKNOX_epervier();
        console.log("ZKNOX_epervier deployed at:", address(epervierVerifier));
        console.log("");
        
        // 2. Deploy library contracts
        console.log("2. Deploying library contracts...");
        
        messageParser = new MessageParserContract();
        console.log("MessageParser deployed at:", address(messageParser));
        
        signatureExtractor = new SignatureExtractorContract();
        console.log("SignatureExtractor deployed at:", address(signatureExtractor));
        
        messageValidation = new MessageValidationContract();
        console.log("MessageValidation deployed at:", address(messageValidation));
        
        addressUtils = new AddressUtilsContract();
        console.log("AddressUtils deployed at:", address(addressUtils));
        
        registrationLogic = new RegistrationLogicContract();
        console.log("RegistrationLogic deployed at:", address(registrationLogic));
        
        unregistrationLogic = new UnregistrationLogicContract();
        console.log("UnregistrationLogic deployed at:", address(unregistrationLogic));
        
        changeAddressLogic = new ChangeAddressLogicContract();
        console.log("ChangeAddressLogic deployed at:", address(changeAddressLogic));
        console.log("");
        
        // 3. Deploy PQRegistryTest with real Epervier address
        console.log("3. Deploying PQRegistryTest with real Epervier verifier...");
        registry = new PQRegistryTest(
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
        nftContract = new PQERC721Test(
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
        
        // Load actor config for testing
        loadActorConfig();
        
        // Test the vectors
        testRegistrationVectors();
        testTransferVectors();
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
        console.log("Danielle:", danielle);
        console.log("Alice Fingerprint:", aliceFingerprint);
        console.log("Bob Fingerprint:", bobFingerprint);
        console.log("Charlie Fingerprint:", charlieFingerprint);
        console.log("Danielle Fingerprint:", danielleFingerprint);
        console.log("");
    }
    
    function testRegistrationVectors() internal {
        console.log("=== TESTING REGISTRATION VECTORS ===");
        
        // Load registration intent vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmationJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Test Alice's registration intent
        console.log("Testing Alice's registration intent...");
        testRegistrationIntent(alice, aliceFingerprint, intentJsonData, "alice");
        
        // Test Bob's registration intent
        console.log("Testing Bob's registration intent...");
        testRegistrationIntent(bob, bobFingerprint, intentJsonData, "bob");
        
        // Test Charlie's registration intent
        console.log("Testing Charlie's registration intent...");
        testRegistrationIntent(charlie, charlieFingerprint, intentJsonData, "charlie");
        
        console.log("");
    }
    
    function testRegistrationIntent(address ethAddress, address pqFingerprint, string memory jsonData, string memory actorName) internal {
        // Parse the vector data for this actor
        string memory actorPath = string.concat(".vectors.", actorName);
        
        // Get the registration intent data
        string memory salt = vm.parseJsonString(jsonData, string.concat(actorPath, ".salt"));
        string memory cs1 = vm.parseJsonString(jsonData, string.concat(actorPath, ".cs1"));
        string memory cs2 = vm.parseJsonString(jsonData, string.concat(actorPath, ".cs2"));
        string memory hint = vm.parseJsonString(jsonData, string.concat(actorPath, ".hint"));
        string memory basePQMessage = vm.parseJsonString(jsonData, string.concat(actorPath, ".base_pq_message"));
        string memory ethNonce = vm.parseJsonString(jsonData, string.concat(actorPath, ".eth_nonce"));
        
        // Parse the ETH signature components
        string memory v = vm.parseJsonString(jsonData, string.concat(actorPath, ".eth_signature.v"));
        string memory r = vm.parseJsonString(jsonData, string.concat(actorPath, ".eth_signature.r"));
        string memory s = vm.parseJsonString(jsonData, string.concat(actorPath, ".eth_signature.s"));
        
        // Convert string data to bytes/uint256
        bytes memory saltBytes = vm.parseBytes(salt);
        uint256[] memory cs1Array = vm.parseJsonUintArray(jsonData, string.concat(actorPath, ".cs1"));
        uint256[] memory cs2Array = vm.parseJsonUintArray(jsonData, string.concat(actorPath, ".cs2"));
        uint256 hintValue = vm.parseJsonUint(jsonData, string.concat(actorPath, ".hint"));
        bytes memory basePQMessageBytes = vm.parseBytes(basePQMessage);
        uint256 ethNonceValue = vm.parseJsonUint(jsonData, string.concat(actorPath, ".eth_nonce"));
        
        uint8 vValue = uint8(vm.parseJsonUint(jsonData, string.concat(actorPath, ".eth_signature.v")));
        bytes32 rValue = bytes32(vm.parseJsonUint(jsonData, string.concat(actorPath, ".eth_signature.r")));
        bytes32 sValue = bytes32(vm.parseJsonUint(jsonData, string.concat(actorPath, ".eth_signature.s")));
        
        // Create the ETH message for registration intent
        // The submitRegistrationIntent function expects an ETH message, not individual components
        // We need to construct the ETH message from the individual components
        bytes memory ethMessage = abi.encodePacked(
            ethNonceValue,
            saltBytes,
            cs1Array,
            cs2Array,
            hintValue,
            basePQMessageBytes
        );
        
        // Submit registration intent
        try registry.submitRegistrationIntent(
            ethMessage,
            vValue,
            rValue,
            sValue
        ) {
            console.log("OK", actorName, "registration intent submitted successfully");
        } catch Error(string memory reason) {
            console.log("FAIL", actorName, "registration intent failed:", reason);
        } catch {
            console.log("FAIL", actorName, "registration intent failed with unknown error");
        }
    }
    
    function testTransferVectors() internal {
        console.log("=== TESTING TRANSFER VECTORS ===");
        
        // Load transfer vectors
        string memory transferJsonData = vm.readFile("test/test_vectors/transfer/pq_transfer_vectors.json");
        
        // Test Alice's transfer
        console.log("Testing Alice's transfer...");
        testPQTransfer(alice, aliceFingerprint, transferJsonData, "alice");
        
        console.log("");
    }
    
    function testPQTransfer(address ethAddress, address pqFingerprint, string memory jsonData, string memory actorName) internal {
        // Parse the vector data for this actor
        string memory actorPath = string.concat(".vectors.", actorName);
        
        // Get the transfer data
        string memory fromFingerprint = vm.parseJsonString(jsonData, string.concat(actorPath, ".from_fingerprint"));
        string memory toFingerprint = vm.parseJsonString(jsonData, string.concat(actorPath, ".to_fingerprint"));
        string memory tokenId = vm.parseJsonString(jsonData, string.concat(actorPath, ".token_id"));
        string memory nonce = vm.parseJsonString(jsonData, string.concat(actorPath, ".nonce"));
        
        // Parse the PQ signature components
        string memory salt = vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_signature.salt"));
        string memory cs1 = vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_signature.cs1"));
        string memory cs2 = vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_signature.cs2"));
        string memory hint = vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_signature.hint"));
        string memory basePQMessage = vm.parseJsonString(jsonData, string.concat(actorPath, ".pq_signature.base_pq_message"));
        
        // Convert string data to bytes/uint256
        address fromFingerprintAddr = vm.parseAddress(fromFingerprint);
        address toFingerprintAddr = vm.parseAddress(toFingerprint);
        uint256 tokenIdValue = vm.parseJsonUint(jsonData, string.concat(actorPath, ".token_id"));
        uint256 nonceValue = vm.parseJsonUint(jsonData, string.concat(actorPath, ".nonce"));
        
        bytes memory saltBytes = vm.parseBytes(salt);
        uint256[] memory cs1Array = vm.parseJsonUintArray(jsonData, string.concat(actorPath, ".pq_signature.cs1"));
        uint256[] memory cs2Array = vm.parseJsonUintArray(jsonData, string.concat(actorPath, ".pq_signature.cs2"));
        uint256 hintValue = vm.parseJsonUint(jsonData, string.concat(actorPath, ".pq_signature.hint"));
        bytes memory basePQMessageBytes = vm.parseBytes(basePQMessage);
        
        // Submit PQ transfer - using the correct function signature
        try nftContract.pqTransferFrom(
            tokenIdValue,
            toFingerprintAddr,
            basePQMessageBytes,
            saltBytes,
            cs1Array,
            cs2Array,
            hintValue
        ) {
            console.log("OK", actorName, "PQ transfer completed successfully");
        } catch Error(string memory reason) {
            console.log("FAIL", actorName, "PQ transfer failed:", reason);
        } catch {
            console.log("FAIL", actorName, "PQ transfer failed with unknown error");
        }
    }
} 