// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// import "forge-std/console.sol";

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {Ownable2Step} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";

contract APIPayment is Ownable2Step, Pausable, EIP712 {
    using SafeERC20 for IERC20;

    // 支持的token
    mapping(address => bool) public supportedTokens;

    // 后端生成 withdraw 签名的密钥
    address public trustedSigner;

    // 用户 withdraw nonce
    mapping(address => uint256) public userNonce;

    // 多签紧急管理员，目前使用：简单数组+批准
    // TODO 修改为Gnosis safe
    address[] public emergencyAdmins;
    mapping(address => bool) public isEmergencyAdmin;
    uint256 public pauseVotes;
    mapping(address => bool) public hasVotedPause;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount, uint256 nonce, uint256 timestamp);
    event WithdrawDebug(bytes32 digest, address signer, address trustSigner);
    event PauseVote(address admin, uint256 votes, bool paused);

    // EIP 712
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address recipient,address token,uint256 amount,uint256 nonce,uint256 validBeforeBlock,uint256 timestamp)"
    );

    constructor(address[] memory tokens, address _trustedSigner, address[] memory _emergencyAdmins, address _owner)
        Ownable(_owner)
        EIP712("API_PAYMENT", "1")
    {
        // 初始化支持的token
        for (uint256 i = 0; i < tokens.length; i++) {
            supportedTokens[tokens[i]] = true;
        }
        trustedSigner = _trustedSigner;
        // 初始化紧急管理员
        for (uint256 i = 0; i < _emergencyAdmins.length; i++) {
            emergencyAdmins.push(_emergencyAdmins[i]);
            isEmergencyAdmin[_emergencyAdmins[i]] = true;
        }
    }

    // 支持 owner 添加/移除支持的 token
    function setSupportedToken(address token, bool isSupported) external onlyOwner {
        supportedTokens[token] = isSupported;
    }

    function setTrustedSigner(address _trustedSigner) external onlyOwner {
        trustedSigner = _trustedSigner;
    }

    // 紧急管理
    // 2/3 多签投票暂停
    function votePause() external {
        require(isEmergencyAdmin[msg.sender], "Not admin");
        require(!hasVotedPause[msg.sender], "Already voted");
        hasVotedPause[msg.sender] = true;
        pauseVotes++;
        emit PauseVote(msg.sender, pauseVotes, false);

        if (pauseVotes * 3 >= emergencyAdmins.length * 2) {
            _pause();
            emit PauseVote(msg.sender, pauseVotes, true);
        }
    }

    function voteUnpause() external {
        require(isEmergencyAdmin[msg.sender], "Not admin");
        require(hasVotedPause[msg.sender], "Did not vote yet");
        hasVotedPause[msg.sender] = false;
        if (pauseVotes > 0) pauseVotes--;
        if (paused() && pauseVotes * 3 < emergencyAdmins.length * 2) {
            _unpause();
        }
    }

    // deposit
    function deposit(uint256 amount, address token) external whenNotPaused {
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
        uint256 timestamp,
        bytes calldata signature
    ) external whenNotPaused {
        require(supportedTokens[token], "Token not supported");
        require(block.number <= validBeforeBlock, "Signature expired");
        require(nonce == userNonce[msg.sender] + 1, "Invalid nonce");

        // 组装 hash（EIP-712）
        bytes32 structHash =
            keccak256(abi.encode(WITHDRAW_TYPEHASH, msg.sender, token, amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        emit WithdrawDebug(digest, signer, trustedSigner); // 新增调试事件
        require(signer == trustedSigner, "Invalid signature");

        userNonce[msg.sender] = nonce; // 先更新nonce再转账，防重入
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount, nonce, timestamp);
    }

    // owner可以转账合约中的balance
    function transferTo(address token, address to, uint256 amount) external onlyOwner {
        require(supportedTokens[token], "Token not supported");
        IERC20(token).safeTransfer(to, amount);
    }

    receive() external payable { revert("ETH not accepted"); }
    fallback() external payable { revert("No fallback"); }
}
