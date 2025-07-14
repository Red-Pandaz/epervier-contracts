// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQERC721Test.sol";
import "../src/PQRegistryTest.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "../src/contracts/MessageParserContract.sol";
import "../src/contracts/SignatureExtractorContract.sol";
import "../src/contracts/MessageValidationContract.sol";
import "../src/contracts/AddressUtilsContract.sol";
import "../src/contracts/RegistrationLogicContract.sol";
import "../src/contracts/UnregistrationLogicContract.sol";
import "../src/contracts/ChangeAddressLogicContract.sol";



contract PQERC721Tests is Test {
    PQERC721Test public nft;
    PQRegistryTest public registry;
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
    
    function setUp() public {
        // Load actor config
        string memory jsonData = vm.readFile(ACTORS_CONFIG_PATH);
        
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
        
        // Deploy NFT contract (without registry in constructor)
        nft = new PQERC721Test("PQ NFT", "PQNFT");
        
        // Initialize the NFT contract with the registry
        nft.initialize(address(registry));
        
        // Initialize the registry with the NFT contract
        address[] memory nftContracts = new address[](1);
        nftContracts[0] = address(nft);
        registry.initializeNFTContracts(nftContracts);
        
        // Register fingerprints for testing
        registerFingerprints();
    }
    
    function registerFingerprints() internal {
        // Load registration test vectors
        string memory intentJsonData = vm.readFile("test/test_vectors/register/registration_intent_vectors.json");
        string memory confirmJsonData = vm.readFile("test/test_vectors/register/registration_confirmation_vectors.json");
        
        // Register Alice
        registerActor("alice", 0, intentJsonData, confirmJsonData);
        
        // Register Bob
        registerActor("bob", 1, intentJsonData, confirmJsonData);
        
        // Register Charlie
        registerActor("charlie", 2, intentJsonData, confirmJsonData);
        
        // Register Danielle
        registerActor("danielle", 3, intentJsonData, confirmJsonData);
    }
    
    function registerActor(string memory actorName, uint256 index, string memory intentJsonData, string memory confirmJsonData) internal {
        // Submit registration intent
        string memory intentVectorPath = string.concat(".registration_intent[", vm.toString(index), "]");
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_message")));
        
        // Parse ETH signature
        uint8 v = uint8(vm.parseUint(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.v"))));
        bytes32 r = vm.parseBytes32(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.r")));
        bytes32 s = vm.parseBytes32(vm.parseJsonString(intentJsonData, string.concat(intentVectorPath, ".eth_signature.s")));
        
        // Submit intent
        registry.submitRegistrationIntent(ethIntentMessage, v, r, s);
        
        // Confirm registration
        string memory confirmVectorPath = string.concat(".registration_confirmation[", vm.toString(index), "]");
        bytes memory pqConfirmationMessage = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_message")));
        bytes memory confirmSalt = vm.parseBytes(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.salt")));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.cs1"));
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.cs2"));
        uint256 confirmHint = vm.parseUint(vm.parseJsonString(confirmJsonData, string.concat(confirmVectorPath, ".pq_signature.hint")));
        
        // Confirm registration
        registry.confirmRegistration(pqConfirmationMessage, confirmSalt, confirmCs1, confirmCs2, confirmHint);
    }
    
    function testConstructor() public {
        assertEq(nft.name(), "PQ NFT");
        assertEq(nft.symbol(), "PQNFT");
    }
    
    function testDisabledTransferFunctions() public {
        // Test that standard ERC721 transfer functions are disabled
        vm.expectRevert("Use pqTransferFrom with PQ signature");
        nft.transferFrom(address(0), address(0), 1);
        
        vm.expectRevert("Use pqTransferFrom with PQ signature");
        nft.safeTransferFrom(address(0), address(0), 1);
        
        vm.expectRevert("Approvals disabled - use pqTransferFrom");
        nft.approve(address(0), 1);
        
        vm.expectRevert("Approvals disabled - use pqTransferFrom");
        nft.setApprovalForAll(address(0), true);
    }
    
    // ============================================================================
    // MINTING TESTS
    // ============================================================================
    
    function testMintFunction() public {
        uint256 expectedTokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        
        // Only registry can mint
        vm.expectRevert("Only registry can mint");
        nft.mint(aliceFingerprint, alice);
        
        // Mock the registry call
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        // Check that the token was minted correctly with deterministic ID
        assertEq(nft.ownerOf(expectedTokenId), aliceFingerprint);
        assertEq(nft.getTokenPQFingerprint(expectedTokenId), aliceFingerprint);
        assertEq(nft.getTokenByPQFingerprint(aliceFingerprint), expectedTokenId);
    }
    
    function testCannotMintDuplicateFingerprint() public {
        uint256 tokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        
        // Mint first token
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        // Store initial state
        address initialOwner = nft.ownerOf(tokenId);
        address initialFingerprint = nft.getTokenPQFingerprint(tokenId);
        uint256 initialTokenId = nft.getTokenByPQFingerprint(aliceFingerprint);
        
        // Try to mint second token with same fingerprint (should return early)
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, bob);
        
        // Verify the state hasn't changed - function returned early
        assertEq(nft.ownerOf(tokenId), initialOwner);
        assertEq(nft.getTokenPQFingerprint(tokenId), initialFingerprint);
        assertEq(nft.getTokenByPQFingerprint(aliceFingerprint), initialTokenId);
    }
    
    function testDeterministicTokenIds() public {
        uint256 tokenId1 = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        uint256 tokenId2 = uint256(keccak256(abi.encodePacked("PQ_TOKEN", bobFingerprint)));
        
        // Mint tokens
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        vm.prank(address(registry));
        nft.mint(bobFingerprint, bob);
        
        // Verify deterministic token IDs
        assertEq(tokenId1, uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint))));
        assertEq(tokenId2, uint256(keccak256(abi.encodePacked("PQ_TOKEN", bobFingerprint))));
        assertEq(nft.ownerOf(tokenId1), aliceFingerprint);
        assertEq(nft.ownerOf(tokenId2), bobFingerprint);
        
        // Verify that the same fingerprint always produces the same token ID
        assertEq(nft.getTokenByPQFingerprint(aliceFingerprint), tokenId1);
        assertEq(nft.getTokenByPQFingerprint(bobFingerprint), tokenId2);
    }
    
    // ============================================================================
    // TRANSFER TESTS WITH REAL VECTORS
    // ============================================================================
    
    function testTransferWithRealVector() public {
        uint256 tokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        console.log("DEBUG: tokenId used in test:", tokenId);
        
        // Mint token to Alice
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        // Load test vector for PQ transfer
        string memory jsonData = vm.readFile("test/test_vectors/transfer/pq_transfer_vectors.json");
        
        // Parse PQ signature components from vector
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.hint"));
        
        // Debug: Print the actual message length and first few bytes
        console.log("DEBUG: pqMessage length from file:", pqMessage.length);
        console.log("DEBUG: pqMessage first 32 bytes (hex):");
        for (uint i = 0; i < 32 && i < pqMessage.length; i++) {
            console.log("DEBUG: pqMessage[", i, "]:", uint8(pqMessage[i]));
        }
        
        // Parse the transfer message to get the tokenId inside
        (uint256 parsedTokenId, address parsedRecipient, uint256 parsedNonce, uint256 parsedTimestamp) = nft.parsePQTransferMessageForTest(pqMessage);
        console.log("DEBUG: tokenId parsed from PQ message:", parsedTokenId);
        console.log("DEBUG: recipient used in test:", bob);
        console.log("DEBUG: recipient parsed from PQ message:", parsedRecipient);
        
        // Transfer using real PQ signature
        nft.pqTransferFrom(tokenId, bob, pqMessage, salt, cs1, cs2, hint);
        
        assertEq(nft.ownerOf(tokenId), bob);
    }
    
    function testTransferWithWrongSignature() public {
        uint256 tokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        
        // Mint token to Alice
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        // Load test vector for wrong signature
        string memory jsonData = vm.readFile("test/test_vectors/transfer/pq_transfer_vectors.json");
        
        // Parse PQ signature components from vector (this should be for wrong fingerprint)
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[3].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[3].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".pq_transfers[3].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".pq_transfers[3].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[3].pq_signature.hint"));
        
        // Transfer should fail with wrong signature
        vm.expectRevert("PQ fingerprint mismatch");
        nft.pqTransferFrom(tokenId, bob, pqMessage, salt, cs1, cs2, hint);
        
        // Token should still be owned by Alice
        assertEq(nft.ownerOf(tokenId), aliceFingerprint);
    }
    
    function testMultiHopTransfers() public {
        // Test multi-hop transfers where Alice's token is transferred multiple times
        // Scenario: Alice's Fingerprint -> Bob's ETH Address -> Charlie's Fingerprint -> Danielle's ETH Address
        // All users are registered with both ETH addresses and PQ fingerprints
        
        // Mint Alice's token
        uint256 aliceTokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        // Load test vectors for multi-hop transfers
        string memory jsonData = vm.readFile("test/test_vectors/transfer/pq_transfer_vectors.json");
        
        // Transfer 1: Alice's Fingerprint -> Bob's ETH Address (signed by Alice)
        bytes memory pqMessage1 = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_message"));
        bytes memory salt1 = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.salt"));
        uint256[] memory cs1_1 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs1");
        uint256[] memory cs2_1 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs2");
        uint256 hint1 = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.hint"));
        
        nft.pqTransferFrom(aliceTokenId, bob, pqMessage1, salt1, cs1_1, cs2_1, hint1);
        
        // Verify Bob owns Alice's token
        assertTrue(nft.isTokenOwner(aliceTokenId, bob));
        assertFalse(nft.isTokenOwner(aliceTokenId, alice));
        
        // Transfer 2: Bob's Fingerprint -> Charlie's Fingerprint (signed by Bob's PQ key)
        // Note: Bob is now the ETH address owner, but the vector expects Bob's fingerprint to sign
        // This requires Bob to be registered with both ETH address and PQ fingerprint (which he is)
        bytes memory pqMessage2 = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[1].pq_message"));
        bytes memory salt2 = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[1].pq_signature.salt"));
        uint256[] memory cs1_2 = vm.parseJsonUintArray(jsonData, ".pq_transfers[1].pq_signature.cs1");
        uint256[] memory cs2_2 = vm.parseJsonUintArray(jsonData, ".pq_transfers[1].pq_signature.cs2");
        uint256 hint2 = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[1].pq_signature.hint"));
        
        nft.pqTransferFrom(aliceTokenId, charlie, pqMessage2, salt2, cs1_2, cs2_2, hint2);
        
        // Verify Charlie owns Alice's token
        assertTrue(nft.isTokenOwner(aliceTokenId, charlie));
        assertFalse(nft.isTokenOwner(aliceTokenId, bob));
        
        // Transfer 3: Charlie's Fingerprint -> Danielle's ETH Address (signed by Charlie)
        bytes memory pqMessage3 = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[2].pq_message"));
        bytes memory salt3 = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[2].pq_signature.salt"));
        uint256[] memory cs1_3 = vm.parseJsonUintArray(jsonData, ".pq_transfers[2].pq_signature.cs1");
        uint256[] memory cs2_3 = vm.parseJsonUintArray(jsonData, ".pq_transfers[2].pq_signature.cs2");
        uint256 hint3 = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[2].pq_signature.hint"));
        
        nft.pqTransferFrom(aliceTokenId, danielle, pqMessage3, salt3, cs1_3, cs2_3, hint3);
        
        // Verify Danielle owns Alice's token
        assertTrue(nft.isTokenOwner(aliceTokenId, danielle));
        assertFalse(nft.isTokenOwner(aliceTokenId, charlie));
        
        // Final state: Alice's token is owned by Danielle
        assertTrue(nft.isTokenOwner(aliceTokenId, danielle));
        assertFalse(nft.isTokenOwner(aliceTokenId, alice));
        assertFalse(nft.isTokenOwner(aliceTokenId, bob));
        assertFalse(nft.isTokenOwner(aliceTokenId, charlie));
    }
    
    // ============================================================================
    // RE-MINTING PREVENTION TESTS
    // ============================================================================
    
    function testCannotRemintAfterUnregistration() public {
        uint256 tokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        
        // Step 1: Register and mint
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        assertEq(nft.ownerOf(tokenId), aliceFingerprint);
        
        // Step 2: Transfer token away (simulating unregistration)
        string memory jsonData = vm.readFile("test/test_vectors/transfer/pq_transfer_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.hint"));
        
        nft.pqTransferFrom(tokenId, bob, pqMessage, salt, cs1, cs2, hint);
        assertEq(nft.ownerOf(tokenId), bob);
        
        // Step 3: Try to re-mint with same fingerprint (should return early)
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, charlie);
        
        // Step 4: Verify token still exists and wasn't overwritten
        assertEq(nft.ownerOf(tokenId), bob);
        assertEq(nft.getTokenPQFingerprint(tokenId), aliceFingerprint);
        assertEq(nft.getTokenByPQFingerprint(aliceFingerprint), tokenId);
    }
    
    // ============================================================================
    // OWNERSHIP TESTS
    // ============================================================================
    
    function testIsTokenOwner() public {
        uint256 tokenId = uint256(keccak256(abi.encodePacked("PQ_TOKEN", aliceFingerprint)));
        
        // Mint token to Alice
        vm.prank(address(registry));
        nft.mint(aliceFingerprint, alice);
        
        // Alice should be the owner
        assertTrue(nft.isTokenOwner(tokenId, aliceFingerprint));
        
        // Bob should not be the owner
        assertFalse(nft.isTokenOwner(tokenId, bobFingerprint));
        
        // Transfer to Bob using real PQ signature
        string memory jsonData = vm.readFile("test/test_vectors/transfer/pq_transfer_vectors.json");
        bytes memory pqMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_message"));
        bytes memory salt = vm.parseBytes(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(jsonData, ".pq_transfers[0].pq_signature.cs2");
        uint256 hint = vm.parseUint(vm.parseJsonString(jsonData, ".pq_transfers[0].pq_signature.hint"));
        
        nft.pqTransferFrom(tokenId, bob, pqMessage, salt, cs1, cs2, hint);
        
        // Bob should now be the owner
        assertTrue(nft.isTokenOwner(tokenId, bob));
        
        // Alice should no longer be the owner
        assertFalse(nft.isTokenOwner(tokenId, alice));
    }
    
    // ============================================================================
    // ADMIN TESTS
    // ============================================================================
    
    function testSetRegistry() public {
        address newRegistry = address(0x999);
        
        // Only owner can set registry
        vm.prank(address(0x123));
        vm.expectRevert();
        nft.setRegistry(newRegistry);
        
        // Owner can set registry
        nft.setRegistry(newRegistry);
        assertEq(address(nft.registry()), newRegistry);
    }
} 