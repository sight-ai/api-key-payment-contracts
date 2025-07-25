## SightAI API KEY PAYMENT CONTRACT

### how to run test
```
forge install OpenZeppelin/openzeppelin-contracts

forge build

forge test
```

### how to deploy locally with scripts
```
// run local network (http://127.0.0.1:8545)
anvil

// pick one private key from local network as your owner and trustSigner, write it in the env 
// !!! pick one from anvil network, not your own wallet
// assume your private key is 0xXXXXX
export PRIVATE_KEY=<0xXXXXX>


// run depoly scripts
forge script script/Deploy.s.sol --tc Deploy --rpc-url http://127.0.0.1:8545 --broadcast --private-key $PRIVATE_KEY

// then you can get the owner, signer, MockERC20 contract address, API payment contract address
```

### deploy arguments
```
APIPayment contract:
    constructor(address[] memory tokens, address _trustedSigner, address[] _emergencyAdmins, address _owner)

MockERC20 contract:
    constructor(string memory _name, string memory _symbol)
```