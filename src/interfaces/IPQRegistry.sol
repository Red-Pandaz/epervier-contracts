// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IPQRegistry {
    function epervierVerifier() external view returns (address);
    function getRegisteredAddress(address) external view returns (address);
    function registerNFTContract(address) external;
} 