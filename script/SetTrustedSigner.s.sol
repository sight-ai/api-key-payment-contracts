// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";

contract SetTrustedSigner is Script {
    function run() external {
        // Load environment variables
        address payable apiPaymentAddress = payable(vm.envAddress("API_PAYMENT_ADDRESS"));
        address newTrustedSigner = vm.envAddress("NEW_TRUSTED_SIGNER");

        uint256 deployerPK;
        string memory pkMaybe = vm.envOr("PRIVATE_KEY", string(""));
        if (bytes(pkMaybe).length > 0) {
            deployerPK = vm.parseUint(pkMaybe);
        } else {
            string memory mnemonic = vm.envString("MNEMONIC");
            deployerPK = vm.deriveKey(mnemonic, 0);
        }

        vm.startBroadcast(deployerPK);

        APIPayment pay = APIPayment(apiPaymentAddress);

        console2.log("APIPayment contract:    %s", apiPaymentAddress);
        console2.log("Current trusted signer: %s", pay.trustedSigner());
        console2.log("New trusted signer:     %s", newTrustedSigner);

        pay.setTrustedSigner(newTrustedSigner);

        console2.log("Trusted signer updated successfully!");

        vm.stopBroadcast();
    }
}
