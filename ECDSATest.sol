
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract ECDSATest {
    function testRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ECDSA.recover(hash, v, r, s);
    }
}
