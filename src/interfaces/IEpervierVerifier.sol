// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IEpervierVerifier {
    function recover(bytes memory, bytes memory, uint256[] memory, uint256[] memory, uint256) external returns (address);
} 