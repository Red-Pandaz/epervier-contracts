// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import "../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import "./libraries/MessageParser.sol";
import "./interfaces/IEpervierVerifier.sol";
import "./interfaces/IPQRegistry.sol";

/**
 * @title PQERC721
 * @dev ERC721 token with PQ signature-based transfers
 * Standard ERC721 transfer functions are disabled
 * Only pqTransferFrom is allowed, which requires PQ signatures
 */
contract PQERC721 is ERC721, Ownable {
    // Registry contract that handles PQ fingerprint validation
    IPQRegistry public registry;

    // Epervier verifier interface
    IEpervierVerifier public epervierVerifier;

    // Domain separator for PQERC721 transfers (keccak256("PQERC721 Transfer"))
    bytes32 public constant PQ_TRANSFER_DOMAIN_SEPARATOR = 0xf5514acfa26be825f841b1d19d3b102fc708b67a0f729c16164a24d825356df0;

    // Base URI for token metadata
    string private _baseTokenURI;

    // Mapping from token ID to original PQ fingerprint (never changes)
    mapping(uint256 => address) public tokenToOriginalFingerprint;
    
    // Mapping from original PQ fingerprint to token ID (one-to-one, never changes)
    mapping(address => uint256) public originalFingerprintToToken;

    // Mapping from PQ fingerprint to nonce (for replay protection)
    mapping(address => uint256) public pqFingerprintNonces;

    // Events
    event TokenMinted(
        uint256 indexed tokenId,
        address indexed owner,
        address indexed pqFingerprint
    );
    event TokenTransferred(
        uint256 indexed tokenId,
        address indexed from,
        address indexed to,
        address pqFingerprint
    );

    /**
     * @dev Constructor
     * @param name Token name
     * @param symbol Token symbol
     */
    constructor(
        string memory name,
        string memory symbol
    ) ERC721(name, symbol) Ownable(msg.sender) {
        // Registry will be set via initialize function
    }

    /**
     * @dev Mint a new token to a PQ fingerprint
     * Only callable by the registry contract when a fingerprint is paired
     * @param pqFingerprint The PQ fingerprint to mint to
     * @param ethAddress The ETH address associated with the fingerprint
     *
     * NOTE: The registry must be initialized via initialize() before calling this.
     */

    function mint(address pqFingerprint, address ethAddress) external {
        require(address(registry) != address(0), "Registry not initialized");
        require(msg.sender == address(registry), "Only registry can mint");
        require(pqFingerprint != address(0), "Invalid PQ fingerprint");
        require(ethAddress != address(0), "Invalid ETH address");

        // Generate deterministic token ID from fingerprint address
        uint256 tokenId = uint256(
            keccak256(abi.encodePacked("PQ_TOKEN", pqFingerprint))
        );

        // If fingerprint already has a token, just return (don't revert)
        if (_ownerOf(tokenId) != address(0) || originalFingerprintToToken[pqFingerprint] != 0 || tokenToOriginalFingerprint[tokenId] != address(0)) {
            return;
        }

        // Mint the token to the ETH address
        _mint(ethAddress, tokenId);

        // Store the mapping
        tokenToOriginalFingerprint[tokenId] = pqFingerprint;
        originalFingerprintToToken[pqFingerprint] = tokenId;

        // Initialize the nonce for this fingerprint
        pqFingerprintNonces[pqFingerprint] = 0;

        emit TokenMinted(tokenId, ethAddress, pqFingerprint);
    }

    /**
     * @dev Transfer token using PQ signature
     * @param tokenId The token ID to transfer
     * @param to The recipient address
     * @param pqMessage The PQ message to verify (must include domain separator and PQ nonce)
     * @param salt The PQ signature salt
     * @param cs1 The PQ signature cs1 array
     * @param cs2 The PQ signature cs2 array
     * @param hint The PQ signature hint
     *
     * NOTE: The registry must be initialized via initialize() before calling this.
     */
    function pqTransferFrom(
        uint256 tokenId,
        address to,
        bytes memory pqMessage,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint
    ) external {
        require(address(registry) != address(0), "Registry not initialized");
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        require(to != address(0), "Invalid recipient");

        // Get the token's PQ fingerprint (the original owner of the token)
        address tokenPQFingerprint = tokenToOriginalFingerprint[tokenId];
        require(
            tokenPQFingerprint != address(0),
            "Token has no PQ fingerprint"
        );

        // Verify the PQ signature using the registry
        address recoveredFingerprint = verifyPQSignature(
            pqMessage,
            salt,
            cs1,
            cs2,
            hint
        );

        // Extract and validate PQ nonce from the message
        uint256 pqNonce = extractPQNonce(pqMessage);
        uint256 storedNonce = pqFingerprintNonces[recoveredFingerprint];
        
        require(
            storedNonce == pqNonce,
            "Invalid PQ nonce"
        );

        // Validate domain separator in the PQ message
        PQTransferMessage memory msgStruct = parsePQTransferMessage(pqMessage);
        console.logBytes32(msgStruct.domainSeparator);
        console.logBytes32(PQ_TRANSFER_DOMAIN_SEPARATOR);
        emit DomainSeparatorDebug(msgStruct.domainSeparator, PQ_TRANSFER_DOMAIN_SEPARATOR);
        require(
            msgStruct.domainSeparator == PQ_TRANSFER_DOMAIN_SEPARATOR,
            "Invalid domain separator in PQ message"
        );

        // Get the current token owner
        address currentOwner = ownerOf(tokenId);

        // Check that the recovered fingerprint can transfer this token:
        // 1. The recovered fingerprint is the current owner, OR
        // 2. The current owner is an ETH address that's mapped to the recovered fingerprint
        bool isFingerprintOwner = (currentOwner == recoveredFingerprint);
        bool isCurrentOwnerMappedToRecovered = false;
        
        // Only check registry mapping if current owner is an ETH address (not a fingerprint)
        if (currentOwner != recoveredFingerprint) {
            // Check if current owner is an ETH address mapped to the recovered fingerprint
            isCurrentOwnerMappedToRecovered = (currentOwner == registry.getRegisteredAddress(recoveredFingerprint));
        }

        require(
            isFingerprintOwner || isCurrentOwnerMappedToRecovered,
            "PQ fingerprint mismatch"
        );

        // Get the current owner
        address from = ownerOf(tokenId);
        
        // Transfer the token
        _transfer(from, to, tokenId);
        
        // DO NOT update tokenToPQFingerprint or pqFingerprintToToken - they represent the original fingerprint
        // The tokenToPQFingerprint and pqFingerprintToToken represent the original owner's fingerprint, not the current owner
        
        // Increment the nonce to prevent replay attacks
        pqFingerprintNonces[recoveredFingerprint]++;
        
        emit TokenTransferred(tokenId, from, to, tokenPQFingerprint);
    }

    /**
     * @dev PQ Transfer Message Structure:
     * - Domain Separator (32 bytes)
     * - Token ID (32 bytes)
     * - Recipient Address (20 bytes)
     * - PQ Nonce (32 bytes)
     * - Timestamp (32 bytes)
     * Total: 148 bytes
     */
    struct PQTransferMessage {
        bytes32 domainSeparator;
        uint256 tokenId;
        address recipient;
        uint256 pqNonce;
        uint256 timestamp;
    }

    /**
     * @dev Parse a PQ transfer message into its components
     * @param pqMessage The PQ message to parse
     * @return message The parsed message structure
     */
    function parsePQTransferMessage(
        bytes memory pqMessage
    ) internal pure returns (PQTransferMessage memory message) {
        require(pqMessage.length == 148, "Invalid message length");
        
        // Parse domain separator (first 32 bytes)
        bytes32 domainSeparator;
        assembly {
            domainSeparator := mload(add(pqMessage, 32))
        }
        message.domainSeparator = domainSeparator;
        
        // Parse token ID (next 32 bytes)
        uint256 tokenId;
        assembly {
            tokenId := mload(add(pqMessage, 64))
        }
        message.tokenId = tokenId;
        
        // Parse recipient address (next 20 bytes)
        address recipient;
        assembly {
            recipient := shr(96, mload(add(pqMessage, 84)))
        }
        require(recipient != address(0), "Invalid recipient");
        message.recipient = recipient;
        
        // Parse PQ nonce (next 32 bytes)
        uint256 pqNonce;
        assembly {
            pqNonce := mload(add(pqMessage, 116))
        }
        message.pqNonce = pqNonce;
        
        // Parse timestamp (next 32 bytes)
        uint256 messageTimestamp;
        assembly {
            messageTimestamp := mload(add(pqMessage, 148))
        }
        message.timestamp = messageTimestamp;
    }

    /**
     * @dev Verify a PQ signature and return the recovered fingerprint
     * @param pqMessage The PQ message to verify
     * @param salt The PQ signature salt
     * @param cs1 The PQ signature cs1 array
     * @param cs2 The PQ signature cs2 array
     * @param hint The PQ signature hint
     * @return The recovered PQ fingerprint address
     */
    function verifyPQSignature(
        bytes memory pqMessage,
        bytes memory salt,
        uint256[] memory cs1,
        uint256[] memory cs2,
        uint256 hint
    ) internal returns (address) {
        return epervierVerifier.recover(pqMessage, salt, cs1, cs2, hint);
    }

    /**
     * @dev Validate domain separator in the PQ message
     * @param pqMessage The PQ message
     * @return True if the domain separator is valid, false otherwise
     */
    function validateDomainSeparator(
        bytes memory pqMessage
    ) internal pure returns (bool) {
        PQTransferMessage memory message = parsePQTransferMessage(pqMessage);
        return message.domainSeparator == PQ_TRANSFER_DOMAIN_SEPARATOR;
    }

    event DomainSeparatorDebug(bytes32 parsed, bytes32 expected);

    /**
     * @dev Extract PQ nonce from the PQ message
     * @param pqMessage The PQ message
     * @return The PQ nonce
     */
    function extractPQNonce(
        bytes memory pqMessage
    ) internal pure returns (uint256) {
        PQTransferMessage memory message = parsePQTransferMessage(pqMessage);
        return message.pqNonce;
    }

    /**
     * @dev Get the PQ fingerprint for a token
     * @param tokenId The token ID
     * @return The PQ fingerprint address
     */
    function getTokenPQFingerprint(
        uint256 tokenId
    ) external view returns (address) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        return tokenToOriginalFingerprint[tokenId];
    }

    /**
     * @dev Get the token ID for a PQ fingerprint
     * @param pqFingerprint The PQ fingerprint
     * @return The token ID (0 if no token exists)
     */
    function getTokenByPQFingerprint(
        address pqFingerprint
    ) external view returns (uint256) {
        return originalFingerprintToToken[pqFingerprint];
    }

    /**
     * @dev Check if an address is the owner of a token (either directly or via PQ fingerprint)
     * @param tokenId The token ID
     * @param account The account to check
     * @return True if the account owns the token
     */
    function isTokenOwner(
        uint256 tokenId,
        address account
    ) external view returns (bool) {
        if (_ownerOf(tokenId) == address(0)) return false;

        address owner = ownerOf(tokenId);
        return account == owner;
    }

    /**
     * @dev Initialize the NFT contract with the registry
     * This should be called after deployment to set up the two-way connection
     * @param _registry The registry contract address
     *
     * NOTE: Must be called before any minting or PQ transfers.
     */
    function initialize(address _registry) external onlyOwner {
        require(_registry != address(0), "Invalid registry address");
        require(address(registry) == address(0), "Already initialized");

        registry = IPQRegistry(_registry);

        // Set the epervier verifier from the registry
        epervierVerifier = IEpervierVerifier(registry.epervierVerifier());

        // Register this NFT contract with the registry
        registry.registerNFTContract(address(this));
    }

    /**
     * @dev Update the registry contract address
     * @param newRegistry The new registry address
     */
    function setRegistry(address newRegistry) external onlyOwner {
        require(newRegistry != address(0), "Invalid registry address");
        registry = IPQRegistry(newRegistry);
    }

    

    // ============================================================================
    // DISABLED ERC721 FUNCTIONS
    // ============================================================================

    /**
     * @dev Disabled - use pqTransferFrom instead
     */
    function transferFrom(address, address, uint256) public pure override {
        revert("Use pqTransferFrom with PQ signature");
    }

    /**
     * @dev Disabled - use pqTransferFrom instead
     */
    function safeTransferFrom(
        address,
        address,
        uint256,
        bytes memory
    ) public pure override {
        revert("Use pqTransferFrom with PQ signature");
    }

    /**
     * @dev Disabled - approvals not needed for PQ-based transfers
     */
    function approve(address, uint256) public pure override {
        revert("Approvals disabled - use pqTransferFrom");
    }

    /**
     * @dev Disabled - approvals not needed for PQ-based transfers
     */
    function setApprovalForAll(address, bool) public pure override {
        revert("Approvals disabled - use pqTransferFrom");
    }

    /**
     * @dev Disabled - approvals not needed for PQ-based transfers
     */
    function getApproved(uint256) public pure override returns (address) {
        revert("Approvals disabled - use pqTransferFrom");
    }

    /**
     * @dev Disabled - approvals not needed for PQ-based transfers
     */
    function isApprovedForAll(
        address,
        address
    ) public pure override returns (bool) {
        revert("Approvals disabled - use pqTransferFrom");
    }

    /**
     * @dev Get the token URI for a given token ID
     * @param tokenId The token ID
     * @return The token URI
     */
    function tokenURI(
        uint256 tokenId
    ) public view virtual override returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");

        string memory base = _baseURI();
        if (bytes(base).length == 0) {
            return "";
        }

        return string(abi.encodePacked(base, _toString(tokenId)));
    }

    /**
     * @dev Get the base URI for token metadata
     * @return The base URI
     */
    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    /**
     * @dev Set the base URI for token metadata
     * @param newBaseURI The new base URI
     */
    function setBaseURI(string memory newBaseURI) external onlyOwner {
        _baseTokenURI = newBaseURI;
    }

    /**
     * @dev Convert uint256 to string
     * @param value The value to convert
     * @return The string representation
     */
    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Convert address to hex string
     * @param addr The address to convert
     * @return The hex string representation
     */
    function toHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = new bytes(40);
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(
                uint8(uint256(uint160(addr)) / (2 ** (8 * (19 - i))))
            );
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            buffer[2 * i] = char(hi);
            buffer[2 * i + 1] = char(lo);
        }
        return string(buffer);
    }

    /**
     * @dev Convert byte to hex character
     * @param b The byte to convert
     * @return c The hex character
     */
    function char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    /**
     * @dev [TESTING ONLY] Public helper to parse a PQ transfer message for test debug
     */
    function parsePQTransferMessageForTest(bytes memory pqMessage) external pure returns (uint256, address, uint256, uint256) {
        PQTransferMessage memory msgStruct = parsePQTransferMessage(pqMessage);
        return (msgStruct.tokenId, msgStruct.recipient, msgStruct.pqNonce, msgStruct.timestamp);
    }

}
