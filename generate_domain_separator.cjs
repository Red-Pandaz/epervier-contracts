const { ethers } = require('ethers');

// PQRegistry contract constants
const DOMAIN_NAME = "PQRegistry";
const DOMAIN_VERSION = "1";

// Function to generate EIP-712 domain separator
function generateDomainSeparator(chainId, contractAddress) {
    const domain = {
        name: "PQRegistry",
        version: "1",
        chainId: 11155420.,
        verifyingContract: this.address
    };
    
    const domainSeparator = ethers.utils._TypedDataEncoder.hashDomain(domain);
    
    return {
        domain,
        domainSeparator,
        domainSeparatorHex: domainSeparator
    };
}

// Generate for different networks
console.log("=== EIP-712 Domain Separator Generator ===\n");

// Ethereum Mainnet
const mainnet = generateDomainSeparator(1, "0x0000000000000000000000000000000000000000");
console.log("Ethereum Mainnet (Chain ID: 1):");
console.log("Domain Separator:", mainnet.domainSeparatorHex);
console.log("Domain:", JSON.stringify(mainnet.domain, null, 2));
console.log();

// Goerli Testnet
const goerli = generateDomainSeparator(5, "0x0000000000000000000000000000000000000000");
console.log("Goerli Testnet (Chain ID: 5):");
console.log("Domain Separator:", goerli.domainSeparatorHex);
console.log("Domain:", JSON.stringify(goerli.domain, null, 2));
console.log();

// Sepolia Testnet
const sepolia = generateDomainSeparator(11155111, "0x0000000000000000000000000000000000000000");
console.log("Sepolia Testnet (Chain ID: 11155111):");
console.log("Domain Separator:", sepolia.domainSeparatorHex);
console.log("Domain:", JSON.stringify(sepolia.domain, null, 2));
console.log();

// Local/Anvil (Chain ID: 31337)
const local = generateDomainSeparator(31337, "0x0000000000000000000000000000000000000000");
console.log("Local/Anvil (Chain ID: 31337):");
console.log("Domain Separator:", local.domainSeparatorHex);
console.log("Domain:", JSON.stringify(local.domain, null, 2));
console.log();

// Function to generate for a specific contract address
function generateForContract(chainId, contractAddress) {
    console.log(`\n=== Custom Contract Address ===`);
    console.log(`Chain ID: ${chainId}`);
    console.log(`Contract Address: ${contractAddress}`);
    const custom = generateDomainSeparator(chainId, contractAddress);
    console.log("Domain Separator:", custom.domainSeparatorHex);
    console.log("Domain:", JSON.stringify(custom.domain, null, 2));
}

// Example: Generate for a specific deployed contract
// Uncomment and modify the line below with your actual contract address
// generateForContract(31337, "0x5FbDB2315678afecb367f032d93F642f64180aa3");

console.log("\n=== Solidity Implementation ===");
console.log(`
// Add this to your PQRegistry contract:

bytes32 public DOMAIN_SEPARATOR;

constructor(address _epervierVerifier, address _console) {
    require(_epervierVerifier != address(0), "Epervier verifier cannot be zero address");
    require(_console != address(0), "Console cannot be zero address");
    
    epervierVerifier = IEpervierVerifier(_epervierVerifier);
    console = IConsole(_console);
    
    // Compute EIP-712 domain separator
    DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(DOMAIN_NAME)),
            keccak256(bytes(DOMAIN_VERSION)),
            block.chainid,
            address(this)
        )
    );
}

// Function to get domain separator (useful for off-chain signing)
function getDomainSeparator() external view returns (bytes32) {
    return DOMAIN_SEPARATOR;
}
`);

console.log("\n=== Usage in Message Signing ===");
console.log(`
// For EIP-712 compliant signatures, use:
bytes32 structHash = keccak256(abi.encode(
    keccak256("YourStructType(field1,field2)"),
    field1Value,
    field2Value
));

bytes32 digest = keccak256(abi.encodePacked(
    "\\x19\\x01",
    DOMAIN_SEPARATOR,
    structHash
));

// Then verify the signature
address signer = ECDSA.recover(digest, v, r, s);
`); 