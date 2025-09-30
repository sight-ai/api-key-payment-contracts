// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";
import "../src/MockERC20.sol";

contract DeployApiHolesky is Script {
    function run() external {
        // Derive private key from mnemonic (more secure for local and testnet)
        string memory mnemonic = vm.envString("MNEMONIC");
        uint256 deployerPK = vm.deriveKey(mnemonic, 0);
        address deployer = vm.addr(deployerPK);
        vm.startBroadcast(deployerPK);
        address usdc = 0x4A4f0184058f54f644baf748D6e628e21999ae0a;

        // 3. Configure supported tokens array
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        // tokens[1] = address(usdt);

        // 4. Configure trustedSigner, owner, and emergencyAdmins
        address trustedSigner = deployer;
        address owner = deployer;
        address[] memory emergencyAdmins = new address[](2);
        emergencyAdmins[0] = deployer;
        emergencyAdmins[1] = 0x000000000000000000000000000000000000dEaD; // Note: Replace with real admin in production

        // 5. Deploy APIPayment contract
        APIPayment pay = new APIPayment(tokens, trustedSigner, emergencyAdmins, owner);

        // Log deployed contract addresses for reference
        console.log("USDC:        %s", address(usdc));
        // console.log("USDT:        %s", address(usdt));
        console.log("APIPayment:  %s", address(pay));
        console.log("trustedSigner: %s", trustedSigner);
        console.log("owner:        %s", owner);

        vm.stopBroadcast();
    }
}
