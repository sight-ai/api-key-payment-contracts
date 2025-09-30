// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";
import "../src/MockERC20.sol";

contract DeployHolesky is Script {
    function run() external {
        // Derive private key from mnemonic (more secure for local and testnet)
        string memory mnemonic = vm.envString("MNEMONIC");
        uint256 deployerPK = vm.deriveKey(mnemonic, 0);
        address deployer = vm.addr(deployerPK);
        vm.startBroadcast(deployerPK);

        // 1. Deploy MockERC20 tokens (USDC and USDT)
        MockERC20 usdc = new MockERC20("SUSDC", "USDC");
        // MockERC20 usdt = new MockERC20("USDT", "USDT");

        // 2. Mint 1,000,000 tokens to deployer for testing
        usdc.mint(deployer, 1_000_000e6);
        // usdt.mint(deployer, 1_000_000e6);

        // 3. Configure supported tokens array
        address[] memory tokens = new address[](1); // Fix: Only using 1 token
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
