// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/APIPayment.sol";
import "../src/MockERC20.sol";

/**
 * @title Deploy Script
 * @author SightAI Team
 * @notice Deployment script for local testing of the APIPayment system
 * @dev Deploys mock tokens and the payment contract with test configuration
 *
 * Usage:
 * 1. Start local network: `anvil`
 * 2. Export private key: `export PRIVATE_KEY=0x...`
 * 3. Run script: `forge script script/Deploy.s.sol:DeployLocal --rpc-url http://127.0.0.1:8545 --broadcast --private-key $PRIVATE_KEY`
 */
contract DeployLocal is Script {
    /**
     * @notice Main deployment function
     * @dev Deploys MockERC20 tokens and APIPayment contract with initial configuration
     *
     * Deployment steps:
     * 1. Deploy mock USDC token
     * 2. Mint initial tokens for testing
     * 3. Configure and deploy APIPayment contract
     * 4. Log deployment addresses for reference
     */
    function run() external {
        // Read deployer private key from environment
        uint256 deployerPK = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPK);

        // Step 1: Deploy Mock ERC20 token (simulating USDC)
        MockERC20 usdc = new MockERC20("USDC", "USDC");

        // Step 2: Mint initial tokens for testing (1M USDC with 6 decimals)
        usdc.mint(msg.sender, 1_000_000e6);

        // Step 3: Configure APIPayment deployment parameters
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        // For local testing, use deployer as all administrative roles
        address trustedSigner = msg.sender;
        address owner = msg.sender;

        // Configure emergency admins (2 required for testing multi-sig)
        address[] memory emergencyAdmins = new address[](2);
        emergencyAdmins[0] = msg.sender;
        emergencyAdmins[1] = 0x000000000000000000000000000000000000dEaD; // Placeholder for second admin - replace in production

        // Log configuration
        console.log("=== Deployment Configuration ===");
        console.log("Trusted Signer: %s", trustedSigner);
        console.log("Owner:          %s", owner);

        // Step 4: Deploy APIPayment contract
        APIPayment pay = new APIPayment(tokens, trustedSigner, emergencyAdmins, owner);

        // Log deployed addresses
        console.log("\n=== Deployed Contracts ===");
        console.log("MockERC20 (USDC): %s", address(usdc));
        console.log("APIPayment:       %s", address(pay));
        console.log("\n=== Initial Setup Complete ===");
        console.log("Deployer has 1,000,000 USDC for testing");

        vm.stopBroadcast();
    }
}
