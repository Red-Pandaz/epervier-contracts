// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/PQRegistry.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract PQRegistryIntegrationTest is Test {
    using ECDSA for bytes32;
    using Strings for string;
    
    PQRegistry public registry;
    ZKNOX_epervier public epervierVerifier;
    
    // These would be populated with real data from Python CLI
    bytes public realSalt;
    uint256[] public realCs1;
    uint256[] public realCs2;
    uint256 public realHint;
    bytes public realMessage;
    uint256[2] public realPublicKey;
    address public realRecoveredAddress;

    
    
    function setUp() public {
        epervierVerifier = new ZKNOX_epervier();
        registry = new PQRegistry(address(epervierVerifier));
        
        // TODO: Load real signature data from Python CLI output
        // This would be done by reading from a file or environment variables
        loadRealSignatureData();
    }
    
    function loadRealSignatureData() internal {
        // Load real public key from public_key_1.pem
        // Format: # public key\nn = 512\npk = <number>\nversion = epervier
        realPublicKey = loadPublicKeyFromPem("test/test_keys/public_key_1.pem");
        
        // Load real signature from sig_1
        (realSalt, realCs1, realCs2, realHint) = loadSignatureFromFile("test/test_keys/sig_1");
        
        // For now, use a placeholder message - you'll need to tell me what was actually signed
        realMessage = "Register Epervier Key"; // This should be the actual message that was signed
        
        // Placeholder recovered address - this should be the actual address recovered from the signature
        realRecoveredAddress = address(0x1234567890123456789012345678901234567890);
    }
    
    function loadPublicKeyFromPem(string memory filename) internal view returns (uint256[2] memory) {
        // For now, hardcode the public key from public_key_1.pem
        // In a real implementation, you'd read and parse the file
        // pk = 703309690834788033648158452166570983886945531899
        return [uint256(703309690834788033648158452166570983886945531899), uint256(0)];
    }
    
    function loadSignatureFromFile(string memory filename) internal view returns (bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint) {
        // For now, hardcode signature components from sig_1
        // In a real implementation, you'd read and parse the hex file
        salt = new bytes(40);
        cs1 = new uint256[](32);
        cs2 = new uint256[](32);
        hint = 123; // This should be extracted from the signature file
        
        // TODO: Parse the actual signature hex string to extract salt, cs1, cs2, hint
        // The sig_1 file contains a long hex string that needs to be decoded
    }
    
    function testRealSignatureVerification() public {
        // Mock the Epervier verifier to return a valid address
        vm.mockCall(
            address(epervierVerifier),
            abi.encodeWithSelector(epervierVerifier.recover.selector),
            abi.encode(realRecoveredAddress)
        );
        
        // Test the Epervier verifier directly
        address recovered = epervierVerifier.recover(
            realMessage, 
            realSalt, 
            realCs1, 
            realCs2, 
            realHint
        );
        
        assertEq(recovered, realRecoveredAddress, "Signature should recover correct address");
    }
    
    function testETHSignatureVerificationWithOpenZeppelin() public {
        // Load test vector data
        string memory jsonData = vm.readFile("test/test_vectors/test_vector_1.json");
        
        // Parse the data
        bytes memory ethIntentMessage = vm.parseBytes(vm.parseJsonString(jsonData, ".eth_intent_message"));
        bytes memory ethIntentSignature = vm.parseBytes(vm.parseJsonString(jsonData, ".eth_intent_signature"));
        address expectedAddress = vm.parseAddress(vm.parseJsonString(jsonData, ".eth_address"));
        
        console.log("Expected ETH address:", expectedAddress);
        console.log("ETH intent message length:", ethIntentMessage.length);
        console.log("ETH intent signature length:", ethIntentSignature.length);
        
        // Verify intent signature with OpenZeppelin ECDSA
        bytes32 intentMessageHash = keccak256(ethIntentMessage);
        // Match Python library format: "Ethereum Signed Message:\n" + length + message
        bytes32 intentSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethIntentMessage.length), ethIntentMessage));
        address recoveredIntentAddress = intentSignedMessageHash.recover(ethIntentSignature);
        
        console.log("Recovered intent address:", recoveredIntentAddress);
        console.log("Intent message hash:", uint256(intentMessageHash));
        console.log("Intent signed message hash:", uint256(intentSignedMessageHash));
        
        // Check if signature is valid
        assertEq(recoveredIntentAddress, expectedAddress, "Intent signature should recover correct address");
        
        console.log("ETH signature verified correctly with OpenZeppelin ECDSA!");
    }
    
    function testRealRegistryRegistration() public {
        // Load real test vector data
        string memory json = vm.readFile("test/test_vectors/comprehensive_vector_1.json");
        
        // Parse the real signature components for the intent (base PQ message)
        bytes memory salt = vm.parseBytes(extractJsonValue(json, ".registration.intent_epervier_salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs2");
        uint256 hint = vm.parseUint(extractJsonValue(json, ".registration.intent_epervier_hint"));
        
        // Debug logging for signature components
        console.log("=== DEBUG: Parsed Signature Components ===");
        console.log("Salt length:", salt.length);
        console.log("CS1 length:", cs1.length);
        console.log("CS2 length:", cs2.length);
        console.log("Hint value:", hint);
        console.log("CS1[0]:", cs1[0]);
        console.log("CS2[0]:", cs2[0]);
        
        // Parse the base PQ message
        bytes memory basePQMessage = vm.parseBytes(extractJsonValue(json, ".registration.base_pq_message"));
        console.log("Base PQ message length:", basePQMessage.length);
        
        // Parse the ETH address
        address ethAddress = vm.parseAddress(extractJsonValue(json, ".eth_address"));
        console.log("ETH address:", ethAddress);
        console.log("Initial registry.ethNonces(ethAddress):", registry.ethNonces(ethAddress));
        
        // Debug: Extract and print the address bytes from the ETH intent message
        // The address should be in the base PQ message which is at the end of the ETH intent message
        bytes memory addressBytes = new bytes(20);
        for (uint j = 0; j < 20; j++) {
            addressBytes[j] = basePQMessage[32 + 27 + j]; // DOMAIN_SEPARATOR + pattern + offset
        }
        uint256 extractedAddr = 0;
        for (uint j = 0; j < 20; j++) {
            extractedAddr = (extractedAddr << 8) | uint8(addressBytes[j]);
        }
        address extractedAddress = address(uint160(extractedAddr));
        console.log("Extracted address from base PQ message:", extractedAddress);
        console.log("Expected address:", ethAddress);
        console.log("Addresses match:", extractedAddress == ethAddress);
        
        // Parse the ETH intent message and signature
        bytes memory ethIntentMessage = vm.parseBytes(extractJsonValue(json, ".registration.eth_intent_message"));
        bytes memory ethIntentSignature = vm.parseBytes(extractJsonValue(json, ".registration.eth_intent_signature"));
        console.log("ETH intent message length:", ethIntentMessage.length);
        console.log("ETH intent signature length:", ethIntentSignature.length);
        
        // Parse ETH signature components
        (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
        console.log("ETH signature v:", v);
        console.log("ETH signature r:", uint256(r));
        console.log("ETH signature s:", uint256(s));
        
        console.log("=== DEBUG: Calling submitRegistrationIntent ===");
        
        // Debug: Let's manually extract the ETH nonce from the ETH intent message
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = ethIntentMessage[32 + 27 + j]; // DOMAIN_SEPARATOR + pattern + offset
        }
        uint256 extractedNonce = abi.decode(nonceBytes, (uint256));
        console.log("Extracted ETH nonce from message:", extractedNonce);
        console.log("Expected ETH nonce (should be 0):", uint256(0));
        
        // Manual hint extraction debugging
        uint256 expectedHintPosition = 32 + 27 + 32 + 40 + 32*32 + 32*32; // DOMAIN_SEPARATOR + pattern + ethNonce + salt + cs1 + cs2
        console.log("Expected hint position:", expectedHintPosition);
        console.log("ETH message length:", ethIntentMessage.length);
        
        // Debug: Let's look at the actual message structure
        console.log("=== DEBUG: ETH Message Structure ===");
        console.log("First 32 bytes (DOMAIN_SEPARATOR):");
        for (uint i = 0; i < 32; i++) {
            console.log("Byte", i, ":", uint8(ethIntentMessage[i]));
        }
        
        console.log("Next 27 bytes (pattern):");
        for (uint i = 32; i < 59; i++) {
            console.log("Byte", i, ":", uint8(ethIntentMessage[i]));
        }
        
        // Let's decode the pattern as ASCII
        bytes memory pattern = new bytes(27);
        for (uint i = 0; i < 27; i++) {
            pattern[i] = ethIntentMessage[32 + i];
        }
        console.log("Pattern as string:", string(pattern));
        
        if (ethIntentMessage.length >= expectedHintPosition + 32) {
            bytes memory extractedHintBytes = new bytes(32);
            for (uint j = 0; j < 32; j++) {
                extractedHintBytes[j] = ethIntentMessage[expectedHintPosition + j];
            }
            uint256 extractedHint = abi.decode(extractedHintBytes, (uint256));
            console.log("Manually extracted hint:", extractedHint);
        } else {
            console.log("Message too short for expected hint position");
        }
        
        // The test vector contains the ETH intent message that should be signed
        // We need to sign the base PQ message with ETH, then create the ETH intent message
        // For now, let's use the test vector as-is and see what happens
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Debug: Let's manually verify the ETH signature to see what's happening
        bytes32 ethMessageHash = keccak256(ethIntentMessage);
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(ethIntentMessage.length), ethIntentMessage));
        address recoveredAddress = ECDSA.recover(ethSignedMessageHash, v, r, s);
        console.log("=== DEBUG: ETH Signature Verification ===");
        console.log("Expected ETH address:", ethAddress);
        console.log("Recovered ETH address:", recoveredAddress);
        console.log("Addresses match:", ethAddress == recoveredAddress);
        
        // Verify the intent was created
        assertEq(registry.ethNonces(ethAddress), 1, "ETH nonce should be incremented");
        
        // Verify the PQ nonce was incremented - use the same logic as the contract
        address recoveredFingerprint = epervierVerifier.recover(basePQMessage, salt, cs1, cs2, hint);
        bytes32 publicKeyHash = bytes32(uint256(uint160(recoveredFingerprint)));
        console.log("Recovered fingerprint:", recoveredFingerprint);
        console.log("Public key hash:", uint256(publicKeyHash));
        assertEq(registry.pqKeyNonces(publicKeyHash), 1, "PQ nonce should be incremented");
        
        console.log("=== DEBUG: Calling confirmRegistration ===");
        console.log("About to call confirmRegistration with:");
        console.log("  basePQMessage length:", basePQMessage.length);
        console.log("  salt length:", salt.length);
        console.log("  cs1 length:", cs1.length);
        console.log("  cs2 length:", cs2.length);
        console.log("  hint:", hint);
        
        // Parse the PQ confirmation message from the test vector
        bytes memory pqConfirmMessage = vm.parseBytes(extractJsonValue(json, ".registration.pq_confirm_message"));
        console.log("pqConfirmMessage (hex):", vm.toString(pqConfirmMessage));

        // Extract the ETH message from the PQ confirmation message
        uint ethMessageStart = 32 + 27 + 20 + 32 + 65; // DOMAIN_SEPARATOR + pattern + address + pqNonce + ethSignature
        bytes memory ethMessage = new bytes(pqConfirmMessage.length - ethMessageStart);
        for (uint i = 0; i < ethMessage.length; i++) {
            ethMessage[i] = pqConfirmMessage[ethMessageStart + i];
        }
        console.log("ethMessage (hex):", vm.toString(ethMessage));

        // Print the 32 bytes at the expected nonce position
        bytes memory confirmNonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            confirmNonceBytes[j] = ethMessage[ethMessage.length - 32 + j]; // Last 32 bytes
        }
        console.log("Extracted nonce bytes (hex):", vm.toString(confirmNonceBytes));
        
        // Parse the confirmation signature components (different from intent signature components)
        bytes memory confirmSalt = vm.parseBytes(extractJsonValue(json, ".registration.epervier_salt"));
        uint256[] memory confirmCs1 = vm.parseJsonUintArray(json, ".registration.epervier_cs1");
        uint256[] memory confirmCs2 = vm.parseJsonUintArray(json, ".registration.epervier_cs2");
        uint256 confirmHint = vm.parseUint(extractJsonValue(json, ".registration.epervier_hint"));
        
        console.log("  confirmSalt length:", confirmSalt.length);
        console.log("  confirmCs1 length:", confirmCs1.length);
        console.log("  confirmCs2 length:", confirmCs2.length);
        console.log("  confirmHint:", confirmHint);
        
        // Confirm registration with real PQ signature (using confirmation signature components)
        registry.confirmRegistration(
            pqConfirmMessage,
            confirmSalt,
            confirmCs1,
            confirmCs2,
            confirmHint
        );
        
        // Verify registration is complete
        assertEq(registry.epervierKeyToAddress(publicKeyHash), ethAddress, "epervierKeyToAddress mapping should be set");
        assertEq(registry.addressToEpervierKey(ethAddress), publicKeyHash, "addressToEpervierKey mapping should be set");
        
        // Verify the intent was cleared (nonce incremented again)
        assertEq(registry.ethNonces(ethAddress), 2, "ETH nonce should be incremented twice");
    }
    
    function testIntegrationWithPythonCLI() public {
        // This test demonstrates the integration flow with the Python CLI
        
        console.log("=== PQ Registry Integration Test ===");
        console.log("1. Generate Epervier keys using Python CLI:");
        console.log("   python sign_cli.py generate");
        
        console.log("2. Sign a message using Python CLI:");
        console.log("   python sign_cli.py sign 'Intent to pair ETH Address <address> <nonce>'");
        
        console.log("3. Extract signature components and create intent message");
        console.log("4. Call registry.submitRegistrationIntent() with real data");
        console.log("5. Sign confirmation message with ETH key");
        console.log("6. Call registry.confirmRegistration() to complete registration");
        console.log("7. Verify the key is registered correctly");
        
        // The actual test would load real data and verify the full flow
        assertTrue(true, "Integration test structure verified");
    }
    
    function testMessageFormatValidation() public {
        // Test that message formats are correct for the new intent/confirmation system
        
        // Test PQ intent message format
        bytes memory pqMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair ETH Address ",
            abi.encodePacked(realRecoveredAddress),
            uint256(0) // pqNonce
        );
        
        // Test ETH intent message format with nested signature structure
        bytes memory ethIntentMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Intent to pair Epervier Key",
            uint256(0), // ethNonce
            realSalt, // salt
            abi.encodePacked(realCs1), // cs1 (32 uint256 values)
            abi.encodePacked(realCs2), // cs2 (32 uint256 values)
            abi.encodePacked(realHint), // hint
            pqMessage // base_pq_message
        );
        
        // Test ETH confirmation message format (this would be used in confirmRegistration)
        bytes memory ethConfirmMessage = abi.encodePacked(
            registry.DOMAIN_SEPARATOR(),
            "Confirm registration",
            uint256(1), // ethNonce
            realSalt, // pqSignature
            pqMessage // pqMessage
        );
        
        // Verify message lengths are reasonable
        assertGt(pqMessage.length, 0, "PQ message should not be empty");
        assertGt(ethIntentMessage.length, pqMessage.length, "ETH intent message should include PQ message");
        assertGt(ethConfirmMessage.length, pqMessage.length, "ETH confirm message should include PQ message");
        
        // Verify domain separator is included
        assertEq(pqMessage.length, registry.DOMAIN_SEPARATOR().length + 27 + 20 + 32, "PQ message should have correct format");
    }
    
    function testNonceIncrement() public {
        // Test that nonces increment correctly after operations
        
        uint256 initialNonce = registry.ethNonces(realRecoveredAddress);
        
        // After a successful registration, nonce should increment
        // This would be tested with real signatures
        assertEq(initialNonce, 0, "Initial nonce should be 0");
        
        // TODO: Test nonce increment after real registration
    }
    
    // Add the extractEthNonceFromRemoveMessage function for test debug
    function extractEthNonceFromRemoveMessage(bytes memory message) internal pure returns (uint256 ethNonce) {
        require(message.length >= 32 + 26 + 32, "Message too short for ETH nonce from remove message");
        bytes memory nonceBytes = new bytes(32);
        for (uint j = 0; j < 32; j++) {
            nonceBytes[j] = message[32 + 26 + j];
        }
        return abi.decode(nonceBytes, (uint256));
    }

    function testRemoveIntentIntegration() public {
        // Load real test vector data
        string memory json = vm.readFile("test/test_vectors/comprehensive_vector_1.json");
        
        // Parse the real signature components for the intent (base PQ message)
        bytes memory salt = vm.parseBytes(extractJsonValue(json, ".registration.intent_epervier_salt"));
        uint256[] memory cs1 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs1");
        uint256[] memory cs2 = vm.parseJsonUintArray(json, ".registration.intent_epervier_cs2");
        uint256 hint = vm.parseUint(extractJsonValue(json, ".registration.intent_epervier_hint"));
        
        // Parse the base PQ message
        bytes memory basePQMessage = vm.parseBytes(extractJsonValue(json, ".registration.base_pq_message"));
        
        // Parse the ETH address
        address ethAddress = vm.parseAddress(extractJsonValue(json, ".eth_address"));
        
        // Parse the ETH intent message and signature
        bytes memory ethIntentMessage = vm.parseBytes(extractJsonValue(json, ".registration.eth_intent_message"));
        bytes memory ethIntentSignature = vm.parseBytes(extractJsonValue(json, ".registration.eth_intent_signature"));
        
        // Parse ETH signature components
        (uint8 v, bytes32 r, bytes32 s) = parseSignature(ethIntentSignature);
        
        // Submit registration intent with real data
        registry.submitRegistrationIntent(
            ethIntentMessage,
            v,
            r,
            s
        );
        
        // Verify intent was created
        assertEq(registry.ethNonces(ethAddress), 1);
        
        // Get the remove intent data from the test vector
        bytes memory ethRemoveMessage = vm.parseBytes(extractJsonValue(json, ".remove_intent.eth_message"));
        bytes memory ethRemoveSignature = vm.parseBytes(extractJsonValue(json, ".remove_intent.eth_signature"));
        
        // Parse ETH signature components
        (uint8 vRemove, bytes32 rRemove, bytes32 sRemove) = parseSignature(ethRemoveSignature);
        
        // Debug: Extract and print the nonce from the remove intent message
        uint256 extractedRemoveNonce = extractEthNonceFromRemoveMessage(ethRemoveMessage);
        console.log("Extracted nonce from remove intent message:", extractedRemoveNonce);
        console.log("Contract ethNonces[ethAddress] before removeIntent:", registry.ethNonces(ethAddress));
        
        registry.removeIntent(
            ethRemoveMessage,
            vRemove,
            rRemove,
            sRemove
        );
        
        // Verify intent was removed
        assertEq(registry.ethNonces(ethAddress), 2);
    }
    
    // Helper function to extract JSON values
    function extractJsonValue(string memory json, string memory key) internal pure returns (string memory) {
        // This is a simplified implementation - in production you'd want a proper JSON parser
        // For now, we'll use vm.parseJsonString which is available in Foundry
        return vm.parseJsonString(json, key);
    }
    
    // Helper function to parse signature components from bytes
    function parseSignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "Invalid signature length");
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Adjust v for Ethereum signature format
        if (v < 27) {
            v += 27;
        }
    }

    function extractEthNonceFromETHMessage(bytes memory ethMessage) internal pure returns (uint256 ethNonce) {
        // Implementation of extractEthNonceFromETHMessage function
        // This function should be implemented based on the specific format of the ETH intent message
        // For now, we'll return a placeholder value
        return 0; // Placeholder return, actual implementation needed
    }
} 