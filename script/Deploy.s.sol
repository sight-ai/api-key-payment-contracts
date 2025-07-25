// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";
import "../src/MockERC20.sol";

contract Deploy is Script {
    function run() external {
        // 读取当前私钥（anvil第一个账户）
        uint256 deployerPK = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPK);

        // 1. 部署两个 MockERC20（usdc, usdt）
        MockERC20 usdc = new MockERC20("USDC", "USDC");

        // 2. 铸币（测试用，给deployer预置余额）
        usdc.mint(msg.sender, 1_000_000e6);

        // 3. 部署 APIPayment
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);

        // trustedSigner、owner、emergencyAdmins 可直接用 msg.sender 作为演示
        address trustedSigner = msg.sender;
        address owner = msg.sender;
        address[] memory emergencyAdmins = new address[](2);
        emergencyAdmins[0] = msg.sender;
        emergencyAdmins[1] = address(0xdead);

        console.log("trustedSigner: %s", trustedSigner);
        console.log("owner:        %s", owner);


        APIPayment pay = new APIPayment(tokens, trustedSigner, emergencyAdmins, owner);

        console.log("USDC: %s", address(usdc));
        console.log("APIPayment: %s", address(pay));

        vm.stopBroadcast();
    }
}