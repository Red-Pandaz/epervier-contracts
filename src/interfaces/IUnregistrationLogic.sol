// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IUnregistrationLogic {
    function submitUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address ethAddress, address pqFingerprint);
    
    function confirmUnregistration(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address ethAddress, address pqFingerprint);
    
    function removeUnregistrationIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address ethAddress);
} 