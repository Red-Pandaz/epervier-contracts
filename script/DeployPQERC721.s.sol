// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/PQERC721.sol";
import "../src/PQRegistry.sol";

contract DeployPQERC721 is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address epervierVerifier = vm.envAddress("EPERVIER_VERIFIER");
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy the registry first
        PQRegistry registry = new PQRegistry(epervierVerifier);
        console.log("PQRegistry deployed at:", address(registry));
        
        // Deploy the NFT contract (without registry in constructor)
        PQERC721 nft = new PQERC721("PQ NFT", "PQNFT");
        console.log("PQERC721 deployed at:", address(nft));
        
        // Initialize the NFT contract with the registry
        nft.initialize(address(registry));
        console.log("NFT contract initialized with registry");
        
        // Initialize the registry with the NFT contract
        address[] memory nftContracts = new address[](1);
        nftContracts[0] = address(nft);
        registry.initializeNFTContracts(nftContracts);
        console.log("Registry initialized with NFT contract");
        
        vm.stopBroadcast();
        
        console.log("Deployment complete!");
        console.log("Registry:", address(registry));
        console.log("NFT Contract:", address(nft));
    }
} 