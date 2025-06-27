// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AddressUtils
 * @dev Library for address conversion utilities
 */
library AddressUtils {
    
    /**
     * @dev Convert address to bytes32
     * @param a The address to convert
     * @return The address as bytes32
     */
    function addressToBytes32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /**
     * @dev Convert bytes32 to address
     * @param b The bytes32 to convert
     * @return The bytes32 as address
     */
    function bytes32ToAddress(bytes32 b) internal pure returns (address) {
        return address(uint160(uint256(b)));
    }
}

