// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IAddressUtils
 * @dev Interface for AddressUtils contract
 */
interface IAddressUtils {
    
    /**
     * @dev Convert address to bytes32
     * @param a The address to convert
     * @return The address as bytes32
     */
    function addressToBytes32(address a) external pure returns (bytes32);
    
    /**
     * @dev Convert bytes32 to address
     * @param b The bytes32 to convert
     * @return The bytes32 as address
     */
    function bytes32ToAddress(bytes32 b) external pure returns (address);
} 