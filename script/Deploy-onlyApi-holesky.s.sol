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
        address usdc = 0x4A4f0184058f54f644baf748D6e628e21999ae0a;

        // 3. 构造 tokens 数组
        address[] memory tokens = new address[](1);
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
