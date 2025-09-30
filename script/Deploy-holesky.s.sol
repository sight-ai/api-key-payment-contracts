// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";
import "../src/MockERC20.sol";

contract Deploy is Script {
    function run() external {
        // 助记词推导私钥（更安全，适用于本地和测试网）
        string memory mnemonic = vm.envString("MNEMONIC");
        uint256 deployerPK = vm.deriveKey(mnemonic, 0);
        address deployer = vm.addr(deployerPK);
        vm.startBroadcast(deployerPK);

        // 1. 部署两个 MockERC20（USDC 和 USDT）
        MockERC20 usdc = new MockERC20("SUSDC", "USDC");
        // MockERC20 usdt = new MockERC20("USDT", "USDT");

        // 2. 给 deployer 各铸 1_000_000 个 token
        usdc.mint(deployer, 1_000_000e6);
        // usdt.mint(deployer, 1_000_000e6);

        // 3. 构造 tokens 数组
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        // tokens[1] = address(usdt);

        // 4. 构造 trustedSigner、owner、emergencyAdmins
        address trustedSigner = deployer;
        address owner = deployer;
        address[] memory emergencyAdmins = new address[](2);
        emergencyAdmins[0] = deployer;
        emergencyAdmins[1] = address(0xdead);

        // 5. 部署 APIPayment
        APIPayment pay = new APIPayment(tokens, trustedSigner, emergencyAdmins, owner);

        // 打印合约地址方便记录
        console.log("USDC:        %s", address(usdc));
        // console.log("USDT:        %s", address(usdt));
        console.log("APIPayment:  %s", address(pay));
        console.log("trustedSigner: %s", trustedSigner);
        console.log("owner:        %s", owner);

        vm.stopBroadcast();
    }
}
