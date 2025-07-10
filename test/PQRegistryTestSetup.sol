// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistryTest.sol";
import "../src/PQERC721Test.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";

/**
 * @title PQRegistryTestSetup
 * @dev Base contract for PQRegistry tests that provides common setup functionality
 */
contract PQRegistryTestSetup is Test {
    // Core contracts
    PQRegistryTest public registry;
    PQERC721Test public nft;
    ZKNOX_epervier public zknoxVerifier;
    
    // Modular contract variables
    MessageParserContract public messageParser;
    SignatureExtractorContract public signatureExtractor;
    MessageValidationContract public messageValidation;
    AddressUtilsContract public addressUtils;
    RegistrationLogicContract public registrationLogic;
    UnregistrationLogicContract public unregistrationLogic;
    ChangeAddressLogicContract public changeAddressLogic;
    
    // Domain separator for EIP-712
    bytes32 public constant DOMAIN_SEPARATOR = keccak256("PQRegistry");
    
    // Load actor config
    string public constant ACTORS_CONFIG_PATH = "test/test_keys/actors_config.json";
    
    // Test addresses from actor config (base setup)
    address public baseAlice;
    address public baseBob;
    address public baseCharlie;
    address public baseDanielle;
    
    // Test fingerprints from actor config (base setup)
    address public baseAliceFingerprint;
    address public baseBobFingerprint;
    address public baseCharlieFingerprint;
    address public baseDanielleFingerprint;
    
    function setUp() public virtual {
        // Load actor config
        string memory jsonData = vm.readFile(ACTORS_CONFIG_PATH);
        
        // Parse addresses
        baseAlice = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.alice.eth_address"));
        baseBob = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.bob.eth_address"));
        baseCharlie = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.charlie.eth_address"));
        baseDanielle = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.danielle.eth_address"));
        
        // Parse fingerprints
        baseAliceFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.alice.pq_fingerprint"));
        baseBobFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.bob.pq_fingerprint"));
        baseCharlieFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.charlie.pq_fingerprint"));
        baseDanielleFingerprint = vm.parseAddress(vm.parseJsonString(jsonData, ".actors.danielle.pq_fingerprint"));
        
        // Deploy ZKNOX verifier
        zknoxVerifier = new ZKNOX_epervier();
        
        // Deploy the modular registry with all contract addresses
        // First deploy the library contracts
        messageParser = new MessageParserContract();
        signatureExtractor = new SignatureExtractorContract();
        messageValidation = new MessageValidationContract();
        addressUtils = new AddressUtilsContract();
        
        // Deploy the business logic contracts
        registrationLogic = new RegistrationLogicContract();
        unregistrationLogic = new UnregistrationLogicContract();
        changeAddressLogic = new ChangeAddressLogicContract();
        
        // Deploy the main registry with all contract addresses
        registry = new PQRegistryTest(
            address(zknoxVerifier),
            address(messageParser),
            address(messageValidation),
            address(signatureExtractor),
            address(addressUtils),
            address(registrationLogic),
            address(unregistrationLogic),
            address(changeAddressLogic)
        );
        
        // Deploy NFT contract for testing
        nft = new PQERC721Test("Test PQ NFT", "TPQNFT");
        
        // Initialize the NFT contract with the registry
        nft.initialize(address(registry));
        
        // Initialize the registry with the NFT contract
        address[] memory nftContracts = new address[](1);
        nftContracts[0] = address(nft);
        registry.initializeNFTContracts(nftContracts);
    }
} 