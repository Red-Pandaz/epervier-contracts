// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/ETHFALCON/ZKNOX_epervier.sol";

contract DeployLocalEpervier is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        console.log("Deploying ZKNOX_epervier contract...");
        
        ZKNOX_epervier epervier = new ZKNOX_epervier();
        
        console.log("ZKNOX_epervier deployed at:", address(epervier));
        
        vm.stopBroadcast();
    }
} 