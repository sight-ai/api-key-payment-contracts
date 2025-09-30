# SightAI API Key Payment Contracts

[![Tests](https://github.com/sight-ai/api-key-payment-contracts/actions/workflows/test.yml/badge.svg)](https://github.com/sight-ai/api-key-payment-contracts/actions/workflows/test.yml)
[![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.20-blue)](https://docs.soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure and efficient smart contract system for managing API key payments with ERC20 tokens on EVM-compatible blockchains.

## Overview

SightAI API Key Payment Contracts provide a decentralized payment infrastructure for API monetization. The system enables users to deposit ERC20 tokens and authorize withdrawals through cryptographically secure signatures, perfect for pay-per-use API services.

### Key Features

- **🔐 Secure Withdrawals**: EIP-712 signature-based authorization ensures only valid withdrawals
- **💰 Multi-Token Support**: Accept payments in multiple whitelisted ERC20 tokens
- **🛡️ Emergency Controls**: Multi-signature emergency pause mechanism for incident response
- **⚡ Gas Efficient**: Optimized for minimal gas consumption
- **🔍 Fully Auditable**: Comprehensive event logging for all critical operations
- **🧪 Battle-Tested**: Extensive test coverage with 19+ test scenarios

## Installation

### Using Foundry

```bash
forge install sight-ai/api-key-payment-contracts
```

Add to your `remappings.txt`:
```
@sight-ai/contracts/=lib/api-key-payment-contracts/src/
```

### Using npm

```bash
npm install @sight-ai/api-key-payment-contracts
```

### Using yarn

```bash
yarn add @sight-ai/api-key-payment-contracts
```

## Usage

### Basic Integration

```solidity
import "@sight-ai/contracts/APIPayment.sol";

// Deploy with configuration
address[] memory supportedTokens = [USDC, USDT];
address trustedSigner = 0x...; // Backend signer address
address[] memory emergencyAdmins = [admin1, admin2, admin3];

APIPayment payment = new APIPayment(
    supportedTokens,
    trustedSigner,
    emergencyAdmins,
    owner
);
```

### User Deposits

```solidity
// User approves token spending
IERC20(token).approve(address(payment), amount);

// User deposits tokens
payment.deposit(token, amount);
```

### Signature-Based Withdrawals

Backend generates EIP-712 signature:
```javascript
const domain = {
  name: "APIPayment",
  version: "1",
  chainId: chainId,
  verifyingContract: paymentAddress
};

const types = {
  Withdraw: [
    { name: "user", type: "address" },
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "expireBlock", type: "uint256" }
  ]
};

const signature = await signer._signTypedData(domain, types, withdrawData);
```

User withdraws with signature:
```solidity
payment.withdraw(token, amount, nonce, expireBlock, signature);
```

## Development

### Prerequisites

- [Foundry](https://getfoundry.sh/) - Solidity development framework
- [Node.js](https://nodejs.org/) >= 16.0.0 (for scripts)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/sight-ai/api-key-payment-contracts.git
cd api-key-payment-contracts
```

2. Install dependencies:
```bash
forge install
```

3. Build contracts:
```bash
forge build
```

### Testing

Run the comprehensive test suite:

```bash
# Run all tests
forge test

# Run with gas reporting
forge test --gas-report

# Run with verbose output
forge test -vvv

# Run specific test
forge test --match-test testWithdrawSuccess

# Run with coverage
forge coverage
```

### Local Deployment

1. Start local blockchain:
```bash
anvil
```

2. Deploy contracts (in new terminal):
```bash
# Set deployer private key from anvil output
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Run deployment script
forge script script/Deploy.s.sol:Deploy \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast \
  --private-key $PRIVATE_KEY
```

### Code Quality

Format code:
```bash
forge fmt
```

Check formatting:
```bash
forge fmt --check
```

## Architecture

### Contract Structure

```
src/
├── APIPayment.sol      # Main payment processing contract
└── MockERC20.sol       # ERC20 token for testing

test/
└── APIPayment.t.sol    # Comprehensive test suite

script/
└── Deploy.s.sol        # Deployment script
```

### Security Features

- **Reentrancy Protection**: State updates before external calls
- **Signature Replay Prevention**: Nonce-based validation
- **Access Control**: Role-based permissions for admin functions
- **Emergency Pause**: Multi-sig controlled circuit breaker
- **Input Validation**: Comprehensive parameter checking

### Design Decisions

1. **Non-Upgradeable**: Intentionally immutable for security and trust
2. **EIP-712 Signatures**: Industry standard for structured data signing
3. **Multi-Sig Emergency**: Prevents single point of failure
4. **Token Whitelisting**: Reduces attack surface by limiting accepted tokens
5. **Block-Based Expiry**: Network-agnostic expiration mechanism

## API Reference

### Core Functions

#### `deposit(address token, uint256 amount)`
Deposits ERC20 tokens into the contract.

#### `withdraw(address token, uint256 amount, uint256 nonce, uint256 expireBlock, bytes signature)`
Withdraws tokens using a valid signature from the trusted signer.

#### `emergencyPause()` / `emergencyUnpause()`
Emergency admin functions requiring majority consensus.

### Admin Functions

#### `setSupportedToken(address token, bool supported)`
Owner-only function to manage supported tokens.

#### `setTrustedSigner(address signer)`
Owner-only function to update the trusted signer.

### View Functions

#### `getBalance(address user, address token)`
Returns user's balance for a specific token.

#### `isTokenSupported(address token)`
Checks if a token is whitelisted.

## Security

### Audits

This project follows security best practices but has not undergone formal third-party auditing. Use at your own risk in production environments.

### Bug Bounty

We welcome security researchers to review our code. Please report vulnerabilities responsibly to contact@sightai.io.

### Known Considerations

- **Trusted Signer**: The backend signer key must be secured with industry best practices
- **Block Timing**: Signature expiration relies on block numbers which vary by network
- **Token Approval**: Standard ERC20 approval risks apply

## License

This project is released under the [MIT License](LICENSE).

## Disclaimer

This software is provided "as is", without warranty of any kind. Users acknowledge they are solely responsible for assessing the suitability of this code for their use case and assume all associated risks.

## Contact

- **Website**: [https://sightai.io](https://sightai.io)
- **Email**: contact@sightai.io
- **Discord**: [Join our community](https://discord.gg/Qftd6QJ4)

---

Built with ❤️ by the SightAI team