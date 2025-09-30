# Deployment Scripts

This directory contains deployment scripts for the APIPayment contract system across different networks.

## Scripts Overview

| Script | Network | Purpose | Contract Name |
|--------|---------|---------|---------------|
| `Deploy.s.sol` | Local (Anvil) | Local testing with mock tokens | `DeployLocal` |
| `Deploy-holesky.s.sol` | Holesky Testnet | Deploy with mock USDC | `DeployHolesky` |
| `Deploy-onlyApi-holesky.s.sol` | Holesky Testnet | Deploy API contract only (uses existing USDC) | `DeployApiHolesky` |
| `DeployBase.s.sol` | Base Mainnet | Production deployment on Base | `DeployBase` |
| `DeployBaseTestnet.s.sol` | Base Testnet | Testing on Base testnet | `DeployBaseTest` |

## Environment Variables

All scripts support the following environment variables:

- `PRIVATE_KEY`: Direct private key (format: `0x...`)
- `MNEMONIC`: BIP39 mnemonic phrase for key derivation
- Priority: `PRIVATE_KEY` > `MNEMONIC`

## Usage Examples

### Local Development (Anvil)

```bash
# Start local blockchain
anvil

# Deploy using Anvil's default private key
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
forge script script/Deploy.s.sol:DeployLocal --rpc-url http://127.0.0.1:8545 --broadcast --private-key $PRIVATE_KEY
```

### Holesky Testnet

```bash
# Using mnemonic
export MNEMONIC="your twelve word mnemonic phrase here"
forge script script/Deploy-holesky.s.sol:DeployHolesky --rpc-url $HOLESKY_RPC --broadcast

# Deploy only API contract (using existing USDC)
forge script script/Deploy-onlyApi-holesky.s.sol:DeployApiHolesky --rpc-url $HOLESKY_RPC --broadcast
```

### Base Network

```bash
# Base Testnet
export MNEMONIC="your twelve word mnemonic phrase here"
forge script script/DeployBaseTestnet.s.sol:DeployBaseTest --rpc-url https://sepolia.base.org --broadcast

# Base Mainnet (⚠️ PRODUCTION - Use with caution!)
forge script script/DeployBase.s.sol:DeployBase --rpc-url https://mainnet.base.org --broadcast
```

## Token Addresses

### Base Network
- **Mainnet USDC**: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
- **Testnet USDC**: `0x036CbD53842c5426634e7929541eC2318f3dCF7e`

### Holesky Testnet
- **Mock USDC (deployed)**: Created by script
- **Existing USDC**: `0x4A4f0184058f54f644baf748D6e628e21999ae0a` (used in API-only deployment)

## Security Considerations

⚠️ **Important Security Notes:**

1. **Emergency Admins**: 
   - Default scripts use deployer address and placeholder (`0xdead`)
   - **MUST** be replaced with real, secure addresses in production
   - Should be different addresses to prevent single point of failure

2. **Trusted Signer**: 
   - Default scripts use deployer address
   - **MUST** use separate secure wallet/multi-sig in production
   - Consider hardware wallet or MPC solution

3. **Owner Address**: 
   - Default scripts use deployer address
   - **MUST** use multi-sig with timelock in production
   - Consider using `Ownable2Step` for safer ownership transfer

4. **Private Key Management**:
   - Never commit private keys or mnemonics to version control
   - Use environment variables or secure key management systems
   - For production, use hardware wallets or cloud KMS

## Deployment Checklist

Before deploying to production:

- [ ] Replace all placeholder addresses with real secure addresses
- [ ] Set up multi-sig wallets for owner and trusted signer roles
- [ ] Configure proper emergency admins (minimum 3 recommended)
- [ ] Verify token addresses for target network
- [ ] Test deployment on testnet first
- [ ] Audit deployment parameters
- [ ] Have incident response plan ready
- [ ] Document all deployed addresses

## Post-Deployment

After successful deployment:

1. Verify contracts on block explorer
2. Transfer ownership to multi-sig (if not already)
3. Configure monitoring and alerts
4. Test basic operations (deposit/withdraw)
5. Document deployment in project documentation

## Troubleshooting

### Common Issues

1. **"insufficient funds"**: Ensure deployer has enough native token for gas
2. **"nonce too high"**: Reset nonce or wait for pending transactions
3. **"contract size exceeds limit"**: Optimize contract or adjust compiler settings
4. **Array size mismatch**: Check token array initialization matches actual tokens added

### Verification

To verify deployed contracts:

```bash
forge verify-contract <CONTRACT_ADDRESS> <CONTRACT_NAME> \
    --chain <CHAIN_NAME> \
    --etherscan-api-key <API_KEY>
```

## Support

For issues or questions about deployment:
- Check the main [README.md](../README.md)
- Review test suite for example usage
- Open an issue on GitHub