// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/**
 * @title MockERC20
 * @author SightAI Team
 * @notice A simple ERC20 token implementation for testing purposes
 * @dev This contract should only be used in test environments, not in production
 *
 * Features:
 * - 6 decimal precision (similar to USDC/USDT)
 * - Unrestricted minting for easy test setup
 * - Basic ERC20 functionality without advanced features
 */
contract MockERC20 is IERC20 {
    // ============ State Variables ============

    /// @notice Token name (e.g., "Mock USDC")
    string public name;

    /// @notice Token symbol (e.g., "mUSDC")
    string public symbol;

    /// @notice Number of decimals for token precision
    /// @dev Set to 6 to simulate USDC/USDT behavior
    uint8 public decimals = 6;

    /// @notice Total supply of tokens in circulation
    uint256 public override totalSupply;

    /// @notice Mapping of account balances
    /// @dev account address => token balance
    mapping(address => uint256) public override balanceOf;

    /// @notice Mapping of spending allowances
    /// @dev owner address => spender address => allowance amount
    mapping(address => mapping(address => uint256)) public override allowance;

    // ============ Constructor ============

    /**
     * @notice Creates a new mock ERC20 token
     * @param _name Name of the token
     * @param _symbol Symbol of the token
     */
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    // ============ Mint Function ============

    /**
     * @notice Mints new tokens to a specified address
     * @dev No access control - only use in test environments
     * @param to Address to receive the minted tokens
     * @param amount Amount of tokens to mint (with decimals)
     */
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    // ============ ERC20 Functions ============

    /**
     * @notice Transfers tokens from msg.sender to recipient
     * @param to Recipient address
     * @param amount Amount of tokens to transfer
     * @return bool Always returns true on success, reverts on failure
     */
    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Approves a spender to transfer tokens on behalf of msg.sender
     * @param spender Address authorized to spend tokens
     * @param amount Maximum amount spender is authorized to transfer
     * @return bool Always returns true
     */
    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Transfers tokens from one address to another using allowance
     * @dev Caller must have sufficient allowance from 'from' address
     * @param from Address to transfer tokens from
     * @param to Address to transfer tokens to
     * @param amount Amount of tokens to transfer
     * @return bool Always returns true on success, reverts on failure
     */
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }
}
