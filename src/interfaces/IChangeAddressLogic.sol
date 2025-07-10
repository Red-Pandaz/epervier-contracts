// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IChangeAddressLogic {
    function submitChangeETHAddressIntent(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address oldEthAddress, address newEthAddress, address pqFingerprint);
    
    function confirmChangeETHAddress(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address oldEthAddress, address newEthAddress, address pqFingerprint);
    
    function removeChangeETHAddressIntentByETH(
        bytes calldata ethMessage,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address ethAddress);
    
    function removeChangeETHAddressIntentByPQ(
        bytes calldata pqMessage,
        bytes calldata salt,
        uint256[] calldata cs1,
        uint256[] calldata cs2,
        uint256 hint
    ) external returns (address ethAddress);
} 