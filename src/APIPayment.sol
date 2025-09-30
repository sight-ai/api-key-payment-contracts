// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {Ownable2Step} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";

/**
 * @title APIPayment
 * @author SightAI Team
 * @notice Manages API key payments with ERC20 tokens using signature-based withdrawals
 * @dev Implements EIP-712 for secure signature verification and multi-sig emergency controls
 *
 * This contract enables:
 * - Users to deposit supported ERC20 tokens for API usage
 * - Backend-authorized withdrawals via EIP-712 signatures
 * - Emergency pause mechanism with multi-signature voting
 * - Owner-controlled token whitelist and configuration
 */
contract APIPayment is Ownable2Step, Pausable, EIP712 {
    using SafeERC20 for IERC20;

    // ============ State Variables ============

    /// @notice Mapping of supported ERC20 tokens
    /// @dev token address => is supported
    mapping(address => bool) public supportedTokens;

    /// @notice Address authorized to sign withdrawal requests
    /// @dev Should be a secure backend wallet
    address public trustedSigner;

    /// @notice Tracks user withdrawal nonces to prevent replay attacks
    /// @dev user address => current nonce
    mapping(address => uint256) public userNonce;

    /// @notice List of emergency admin addresses
    /// @dev Used for multi-sig pause functionality
    address[] public emergencyAdmins;

    /// @notice Mapping to check if an address is an emergency admin
    mapping(address => bool) public isEmergencyAdmin;

    /// @notice Current number of votes for pausing the contract
    uint256 public pauseVotes;

    /// @notice Tracks if an admin has voted for pause
    /// @dev admin address => has voted
    mapping(address => bool) public hasVotedPause;

    // ============ Events ============

    /// @notice Emitted when a user deposits tokens
    /// @param user Address of the depositor
    /// @param token Address of the deposited token
    /// @param amount Amount of tokens deposited
    event Deposit(address indexed user, address indexed token, uint256 amount);

    /// @notice Emitted when a user withdraws tokens
    /// @param user Address of the withdrawer
    /// @param token Address of the withdrawn token
    /// @param amount Amount of tokens withdrawn
    /// @param nonce Nonce used for this withdrawal
    /// @param timestamp Timestamp included in the signature
    event Withdraw(address indexed user, address indexed token, uint256 amount, uint256 nonce, uint256 timestamp);

    /// @notice Emitted when an admin votes for pause/unpause
    /// @param admin Address of the voting admin
    /// @param votes Current total votes
    /// @param paused Whether the contract is now paused
    event PauseVote(address admin, uint256 votes, bool paused);
    event UnpausedByVote(address indexed admin, uint256 votes);
    event TrustedSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event SupportedTokenUpdated(address indexed token, bool isSupported);

    // ============ Constants ============

    /// @notice EIP-712 type hash for withdrawal authorization
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address recipient,address token,uint256 amount,uint256 nonce,uint256 validBeforeBlock,uint256 timestamp)"
    );

    // ============ Constructor ============

    /**
     * @notice Initializes the payment contract with configuration
     * @param tokens Array of initially supported ERC20 token addresses
     * @param _trustedSigner Address authorized to sign withdrawal requests
     * @param _emergencyAdmins Array of emergency admin addresses for pause functionality
     * @param _owner Address that will own the contract
     */
    constructor(address[] memory tokens, address _trustedSigner, address[] memory _emergencyAdmins, address _owner)
        Ownable(_owner)
        EIP712("API_PAYMENT", "1")
    {
        // Initialize supported tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            supportedTokens[tokens[i]] = true;
        }

        trustedSigner = _trustedSigner;

        // Initialize emergency admins
        for (uint256 i = 0; i < _emergencyAdmins.length; i++) {
            emergencyAdmins.push(_emergencyAdmins[i]);
            isEmergencyAdmin[_emergencyAdmins[i]] = true;
        }
    }


    // ============ Admin Functions ============

    /**
     * @notice Updates whether a token is supported for deposits/withdrawals
     * @dev Only callable by contract owner
     * @param token Address of the ERC20 token
     * @param isSupported Whether the token should be supported
     */
    function setSupportedToken(address token, bool isSupported) external onlyOwner {
        require(token != address(0), "Token zero addr");
        supportedTokens[token] = isSupported;
        emit SupportedTokenUpdated(token, isSupported);
    }

    /**
     * @notice Updates the trusted signer address for withdrawal authorization
     * @dev Only callable by contract owner. Ensure new signer is secure
     * @param _trustedSigner New trusted signer address
     */
    function setTrustedSigner(address _trustedSigner) external onlyOwner {
        require(trustedSigner != _trustedSigner, "Signer no change");
        address old = trustedSigner;
        trustedSigner = _trustedSigner;
        emit TrustedSignerUpdated(old, _trustedSigner);
    }

    // ============ Emergency Functions ============

    /**
     * @notice Allows emergency admin to vote for pausing the contract
     * @dev Requires 2/3 majority of emergency admins to pause
     * Each admin can only vote once until they vote to unpause
     */
    function votePause() external {
        require(isEmergencyAdmin[msg.sender], "Not admin");
        require(!hasVotedPause[msg.sender], "Already voted");

        hasVotedPause[msg.sender] = true;
        pauseVotes++;
        emit PauseVote(msg.sender, pauseVotes, false);

        // Check if we have 2/3 majority
        if (pauseVotes * 3 >= emergencyAdmins.length * 2) {
            _pause();
            emit PauseVote(msg.sender, pauseVotes, true);
        }
    }

    /**
     * @notice Allows emergency admin to revoke their pause vote
     * @dev Will unpause the contract if votes fall below 2/3 majority
     */
    function voteUnpause() external {
        require(isEmergencyAdmin[msg.sender], "Not admin");
        require(hasVotedPause[msg.sender], "Did not vote yet");

        hasVotedPause[msg.sender] = false;
        if (pauseVotes > 0) pauseVotes--;

        // Unpause if we no longer have 2/3 majority
        if (paused() && pauseVotes * 3 < emergencyAdmins.length * 2) {
            _unpause();
            emit UnpausedByVote(msg.sender, pauseVotes);
        }
    }

    // ============ Core Functions ============

    /**
     * @notice Allows users to deposit supported ERC20 tokens
     * @dev Requires prior token approval. Tokens are held by this contract
     * @param amount Amount of tokens to deposit
     * @param token Address of the ERC20 token to deposit
     */
    function deposit(uint256 amount, address token) external whenNotPaused {
        require(supportedTokens[token], "Token not supported");
        require(amount > 0, "Amount must be positive");

        // Transfer tokens from user to contract
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, token, amount);
    }

    /**
     * @notice Allows users to withdraw tokens with a valid backend signature
     * @dev Signature must be generated by trusted signer with correct nonce
     * @param token Address of the ERC20 token to withdraw
     * @param amount Amount of tokens to withdraw
     * @param nonce Expected nonce (must be current nonce + 1)
     * @param validBeforeBlock Block number before which the signature is valid
     * @param timestamp Timestamp included in the signature for tracking
     * @param signature EIP-712 signature from trusted signer
     */
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
        require(amount > 0, "Amount must be positive");
        require(trustedSigner != address(0), "Signer disabled");

        // Verify EIP-712 signature
        bytes32 structHash =
            keccak256(abi.encode(WITHDRAW_TYPEHASH, msg.sender, token, amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        require(signer == trustedSigner, "Invalid signature");

        userNonce[msg.sender] = nonce; // reentry protection
        require(IERC20(token).balanceOf(address(this)) >= amount, "Insufficient vault");
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount, nonce, timestamp);
    }

    /**
     * @notice Allows owner to transfer contract balance to any address
     * @dev Emergency function for recovering funds. Only callable by owner
     * @param token Address of the ERC20 token to transfer
     * @param to Recipient address
     * @param amount Amount of tokens to transfer
     */
    function transferTo(address token, address to, uint256 amount) external onlyOwner {
        // require(supportedTokens[token], "Token not supported");
        require(token != address(0), "zero token");
        require(to != address(0), "zero to");
        require(amount > 0, "Zero amount");
        require(IERC20(token).balanceOf(address(this)) >= amount, "Insufficient vault");

        IERC20(token).safeTransfer(to, amount);
    }

    receive() external payable {
        revert("ETH not accepted");
    }

    fallback() external payable {
        revert("No fallback");
    }
}
