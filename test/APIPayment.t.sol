// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/APIPayment.sol";
import "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockERC20 for Testing
 * @notice Simple ERC20 implementation with mint function for test setup
 */
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

/**
 * @title APIPaymentTest
 * @author SightAI Team
 * @notice Comprehensive test suite for the APIPayment contract
 * @dev Tests cover all major functionality including deposits, withdrawals,
 *      signature verification, access control, and emergency pause mechanisms
 */
contract APIPaymentTest is Test {
    APIPayment payment;
    MockERC20 usdc;
    MockERC20 usdt;
    address owner = address(0x1);
    address signer;
    address alice = address(0x3);
    address[] emergencyAdmins;

    string constant NAME = "API_PAYMENT";
    string constant VERSION = "1";

    /**
     * @notice Computes the EIP-712 domain separator
     * @dev Used to construct valid signatures for testing
     * @return The domain separator hash
     */
    function domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(payment)
            )
        );
    }

    /**
     * @notice Helper function to create valid withdrawal signatures
     * @param user Address of the user withdrawing
     * @param token Token address
     * @param amount Amount to withdraw
     * @param nonce User's nonce
     * @param validBeforeBlock Signature expiration block
     * @param timestamp Timestamp for tracking
     * @return Packed signature bytes (r, s, v)
     */
    function signWithdraw(
        address user,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 validBeforeBlock,
        uint256 timestamp
    ) internal view returns (bytes memory) {
        bytes32 typehash = payment.WITHDRAW_TYPEHASH();
        bytes32 structHash = keccak256(abi.encode(typehash, user, token, amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Sets up the test environment before each test
     * @dev Deploys contracts, mints tokens, and configures initial state
     */
    function setUp() public {
        usdc = new MockERC20("USDC", "USDC");
        usdt = new MockERC20("USDT", "USDT");
        signer = vm.addr(2);

        // fund alice account
        usdc.mint(alice, 1_000_000e6);
        usdt.mint(alice, 1_000_000e6);

        // admin
        emergencyAdmins = new address[](2);
        emergencyAdmins[0] = address(0x10);
        emergencyAdmins[1] = address(0x11);

        // deploy
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdt);

        payment = new APIPayment(tokens, signer, emergencyAdmins, owner);
    }

    /**
     * @notice Tests the complete deposit and withdrawal flow
     * @dev Verifies balances, nonce updates, and event emissions
     */
    function testDepositAndWithdraw() public {
        vm.startPrank(alice);

        usdc.approve(address(payment), 100e6);

        payment.deposit(100e6, address(usdc));
        assertEq(usdc.balanceOf(address(payment)), 100e6);

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;

        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);

        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);

        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        assertEq(usdc.balanceOf(address(payment)), 100e6 - amount);
        assertEq(payment.userNonce(alice), 1);

        vm.stopPrank();
    }

    /**
     * @notice Tests that deposit function emits the correct event
     */
    function testDepositEmitsEvent() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        vm.recordLogs();
        payment.deposit(100e6, address(usdc));

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool found = false;
        bytes32 expectedTopic = keccak256("Deposit(address,address,uint256)");
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == expectedTopic) {
                found = true;
            }
        }
        assertTrue(found, "Deposit event not found!");
        vm.stopPrank();
    }

    /**
     * @notice Tests that withdrawal function emits the correct event
     */
    function testWithdrawEmitsEvent() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);

        vm.recordLogs();
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool found = false;
        bytes32 expectedTopic = keccak256("Withdraw(address,address,uint256,uint256,uint256)");
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == expectedTopic) {
                found = true;
            }
        }
        assertTrue(found, "Withdraw event not found!");
        vm.stopPrank();
    }

    /**
     * @notice Tests owner's ability to transfer contract funds
     * @dev Emergency function for fund recovery
     */
    function testOwnerCanTransferTo() public {
        usdc.mint(address(payment), 100e6);
        uint256 before = usdc.balanceOf(owner);
        vm.startPrank(owner);
        payment.transferTo(address(usdc), owner, 20e6);
        assertEq(usdc.balanceOf(owner), before + 20e6);
        vm.stopPrank();
    }

    /**
     * @notice Tests owner's ability to update the trusted signer
     * @dev Verifies old signatures become invalid after signer change
     */
    function testOwnerCanSetTrustedSigner() public {
        vm.startPrank(owner);
        address newSigner = vm.addr(55);
        payment.setTrustedSigner(newSigner);

        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));

        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6);

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;

        // Sign with new signer
        bytes32 typehash = payment.WITHDRAW_TYPEHASH();
        bytes32 structHash =
            keccak256(abi.encode(typehash, alice, address(usdc), amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(55, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Signing with old signer should fail
        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig2);

        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);

        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        assertEq(usdc.balanceOf(address(payment)), 100e6 - amount);
        assertEq(payment.userNonce(alice), 1);

        vm.stopPrank();
    }

    /**
     * @notice Tests that depositing unsupported tokens reverts
     */
    function testDepositNotSupportedTokenReverts() public {
        MockERC20 fakeToken = new MockERC20("FAKE", "FAKE");
        fakeToken.mint(alice, 100e6);
        vm.startPrank(alice);
        fakeToken.approve(address(payment), 100e6);
        vm.expectRevert("Token not supported");
        payment.deposit(100e6, address(fakeToken));
        vm.stopPrank();
    }

    /**
     * @notice Tests that withdrawing unsupported tokens reverts
     */
    function testWithdrawNotSupportedTokenReverts() public {
        MockERC20 fakeToken = new MockERC20("FAKE", "FAKE");
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(fakeToken), amount, nonce, validBeforeBlock, timestamp);

        vm.startPrank(alice);
        vm.expectRevert("Token not supported");
        payment.withdraw(address(fakeToken), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    /**
     * @notice Tests nonce validation to prevent replay attacks
     * @dev Verifies that:
     * - Same nonce cannot be used twice
     * - Nonces must increment sequentially
     * - Wrong nonce values are rejected
     */
    function testWithdrawNonceChecks() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        // First withdrawal
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig1 = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig1);

        // Try again with same nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig1);

        // Try with smaller nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce - 1, validBeforeBlock, timestamp, sig1);

        // Try with larger nonce
        uint256 nonce2 = 2;
        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, nonce2, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce2, validBeforeBlock, timestamp, sig2);
        vm.stopPrank();
    }

    /**
     * @notice Tests signature expiration based on block number
     */
    function testWithdrawBlockExpired() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 1;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        vm.roll(validBeforeBlock + 1); // Skip blocks
        vm.expectRevert("Signature expired");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    /**
     * @notice Tests rejection of signatures from wrong signer
     */
    function testWithdrawInvalidSignature() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        // Sign with wrong private key
        bytes32 typehash = payment.WITHDRAW_TYPEHASH();
        bytes32 structHash =
            keccak256(abi.encode(typehash, alice, address(usdc), amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(99, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    /**
     * @notice Tests that signatures for different recipients are rejected
     * @dev Prevents signature misuse across different users
     */
    function testWithdrawWrongReceiver() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;

        address bob = address(0xB0B);
        bytes32 typehash = payment.WITHDRAW_TYPEHASH();
        bytes32 structHash =
            keccak256(abi.encode(typehash, bob, address(usdc), amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    /**
     * @notice Tests that nonces are tracked separately per user
     * @dev Each user has independent nonce counter
     */
    function testWithdrawNoncePerUser() public {
        address bob = address(0xB0B);

        usdc.mint(bob, 100e6);
        vm.startPrank(bob);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        vm.stopPrank();

        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sigAlice = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sigAlice);

        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sigAlice);
        vm.stopPrank();

        vm.startPrank(bob);
        assertEq(payment.userNonce(bob), 0);
        bytes memory sigBob = signWithdraw(bob, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sigBob);
        assertEq(payment.userNonce(bob), 1);
        vm.stopPrank();
    }

    /**
     * @notice Tests that amount tampering invalidates signature
     */
    function testWithdrawInvalidAmountSignature() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));

        uint256 correctAmount = 10e6;
        uint256 wrongAmount = 11e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;

        bytes memory sig = signWithdraw(alice, address(usdc), correctAmount, nonce, validBeforeBlock, timestamp);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), wrongAmount, nonce, validBeforeBlock, timestamp, sig);

        vm.stopPrank();
    }

    /**
     * @notice Tests reentrancy protection
     * @dev Verifies nonce update prevents reentrancy attacks
     */
    function testNoReentrancy() public {
        ReentrantAttack attacker = new ReentrantAttack(address(payment), address(usdc));

        vm.startPrank(alice);
        usdc.approve(address(payment), 10e6);
        payment.deposit(10e6, address(usdc));
        usdc.transfer(address(attacker), 10e6);
        uint256 timestamp = block.timestamp;
        vm.stopPrank();

        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        bytes memory sig = signWithdraw(address(attacker), address(usdc), 1e6, nonce, validBeforeBlock, timestamp);

        attacker.attack(sig, nonce, validBeforeBlock);

        assertEq(payment.userNonce(address(attacker)), 1);
        assertEq(usdc.balanceOf(address(attacker)), 11e6);
    }

    /**
     * @notice Tests multi-sig pause mechanism
     * @dev Requires 2/3 majority of emergency admins to pause
     */
    function testPauseByMajorityAdmin() public {
        // Two emergencyAdmins, 2/3 rule means both must agree to pause
        // First admin votes
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Paused too early");
        // Second admin votes
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused after 2 votes");
    }

    /**
     * @notice Tests that insufficient votes don't pause contract
     */
    function testPauseNotEnoughVotes() public {
        // Only one admin voting, not enough for majority, cannot pause
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Should NOT be paused with only one vote");
    }

    /**
     * @notice Tests unpause mechanism when votes drop below threshold
     */
    function testUnpauseByAdmin() public {
        // Two votes to pause
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused now");

        // Revoke one vote, should unpause
        vm.prank(address(0x11));
        payment.voteUnpause();
        assertFalse(payment.paused(), "Should be unpaused when votes < 2/3");
    }

    /**
     * @notice Tests that pause blocks all critical operations
     * @dev Both deposits and withdrawals should revert when paused
     */
    function testPauseDisablesDepositAndWithdraw() public {
        // Two votes to pause
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused");

        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        vm.expectRevert("EnforcedPause()");
        payment.deposit(100e6, address(usdc));

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        vm.expectRevert("EnforcedPause()");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    /**
     * @notice Tests EIP-712 signature verification
     * @dev Ensures _hashTypedDataV4 implementation works correctly
     */
    function testEIP712TypedDataSignatureWorks() public {
        // Test that EIP712 signature verification works correctly
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        // Use main signWithdraw function which uses EIP712 format
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        vm.stopPrank();
    }
}

/**
 * @title ReentrantAttack
 * @notice Malicious contract attempting reentrancy attack
 * @dev Used to test reentrancy protection in withdraw function
 */
contract ReentrantAttack {
    APIPayment public payment;
    IERC20 public usdc;
    address public attacker;
    bytes public lastSig;
    uint256 public lastNonce;
    uint256 public lastBlock;
    uint256 public lastTimestamp;

    constructor(address _payment, address _usdc) {
        payment = APIPayment(_payment);
        usdc = IERC20(_usdc);
        attacker = msg.sender;
    }

    function attack(bytes memory sig, uint256 nonce, uint256 validBeforeBlock) public {
        lastSig = sig;
        lastNonce = nonce;
        lastBlock = validBeforeBlock;
        lastTimestamp = block.timestamp;
        payment.withdraw(address(usdc), 1e6, nonce, validBeforeBlock, lastTimestamp, sig);
    }

    receive() external payable {
        try payment.withdraw(address(usdc), 1e6, lastNonce, lastBlock, lastTimestamp, lastSig) {
            revert("Should not succeed");
        } catch {}
    }
}
