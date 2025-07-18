// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// import "forge-std/console.sol";

import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ECDSA } from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";

contract APIPayment is Ownable {
    using SafeERC20 for IERC20;

    // 支持的token
    mapping(address => bool) public supportedTokens;

    // 后端生成 withdraw 签名的密钥
    address public trustedSigner;

    // 用户 withdraw nonce
    mapping(address => uint256) public userNonce;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount, uint256 nonce);

    // EIP-712域名分隔 ———— 如果只有这个的payment，可能不需要
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256("Withdraw(address recipient,address token,uint256 amount,uint256 nonce,uint256 validBeforeBlock)");

    constructor(address[] memory tokens, address _trustedSigner, address _owner) Ownable(_owner) {
        // 初始化支持的token
        for (uint i = 0; i < tokens.length; i++) {
            supportedTokens[tokens[i]] = true;
        }
        trustedSigner = _trustedSigner;
        // 初始化 EIP-712 域名分隔
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("API Payment")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // 支持 owner 添加/移除支持的 token
    function setSupportedToken(address token, bool isSupported) external onlyOwner {
        supportedTokens[token] = isSupported;
    }

    function setTrustedSigner(address _trustedSigner) external onlyOwner {
        trustedSigner = _trustedSigner;
    }

    // deposit
    function deposit(uint256 amount, address token) external {
        require(supportedTokens[token], "Token not supported");
        require(amount > 0, "Amount must be positive");
        // transferFrom
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, token, amount);
    }

    // withdraw（user/provider claim）
    function withdraw(
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 validBeforeBlock,
        bytes calldata signature
    ) external {
        require(supportedTokens[token], "Token not supported");
        require(block.number <= validBeforeBlock, "Signature expired");
        require(nonce == userNonce[msg.sender] + 1, "Invalid nonce");

        // 组装 hash（EIP-712）
        bytes32 structHash = keccak256(abi.encode(
            WITHDRAW_TYPEHASH,
            msg.sender,
            token,
            amount,
            nonce,
            validBeforeBlock
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, signature);
        
        // For test
        // console.logBytes32(structHash);
        // console.logBytes32(digest);
        
        require(signer == trustedSigner, "Invalid signature");

        userNonce[msg.sender] = nonce; // 先更新nonce再转账，防重入
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount, nonce);
    }

    // owner可以转账合约中的balance
    function transferTo(address token, address to, uint256 amount) external onlyOwner {
        require(supportedTokens[token], "Token not supported");
        IERC20(token).safeTransfer(to, amount);
    }
}