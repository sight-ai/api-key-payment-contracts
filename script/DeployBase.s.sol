// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";

contract DeployBase is Script {
    function run() external {
        // Use mnemonic or private key
        uint256 deployerPK;
        string memory pkMaybe = vm.envOr("PRIVATE_KEY", string(""));
        if (bytes(pkMaybe).length > 0) {
            deployerPK = vm.parseUint(pkMaybe);
        } else {
            string memory mnemonic = vm.envString("MNEMONIC");
            // Foundry default derivation path: m/44'/60'/0'/0/index
            deployerPK = vm.deriveKey(mnemonic, 0);
        }
        address deployer = vm.addr(deployerPK);

        // Base mainnet native USDC
        address usdc = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

        // Configure supported tokens
        address[] memory tokens = new address[](1);
        tokens[0] = usdc;

        // Basic roles (Production recommendations: use multi-sig/hardware wallet for trustedSigner; Ownable2Step+timelock for owner)
        address trustedSigner = deployer;
        address owner = deployer;

        // Emergency admins (Please replace with real secure addresses, avoid duplicates)
        address[] memory emergencyAdmins = new address[](1);
        emergencyAdmins[0] = deployer;

        vm.startBroadcast(deployerPK);

        APIPayment pay = new APIPayment(tokens, trustedSigner, emergencyAdmins, owner);

        console2.log("== Base Mainnet Deployment ==");
        console2.log("Deployer:     %s", deployer);
        console2.log("USDC:         %s", usdc);
        console2.log("APIPayment:   %s", address(pay));
        console2.log("trustedSigner:%s", trustedSigner);
        console2.log("owner:        %s", owner);

        vm.stopBroadcast();
    }
}
