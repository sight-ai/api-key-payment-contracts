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


interface IReenter {
    function reenter() external;
}

contract EvilERC20 is ERC20 {
    address public immutable payment;

    constructor(address _payment) ERC20("EVIL", "EVIL") {
        payment = _payment;
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    // OZ v5 pattern: unified internal hook
    function _update(address from, address to, uint256 value) internal override {
        // Execute balance update first
        super._update(from, to, value);

        // 当从 APIPayment 转出到“合约地址”时，尝试回调触发重入
        if (from == payment && to.code.length > 0) {
            try IReenter(to).reenter() {} catch {}
        }
    }
}

// Attempts to call withdraw again during token transfer callback (should be blocked by nonce)
contract ReentrantAttack is IReenter {
    APIPayment public payment;
    IERC20 public token;

    bytes public sig;
    uint256 public nonce_;
    uint256 public validBeforeBlock_;
    uint256 public ts_;

    // Need address payable here (because APIPayment has payable fallback)
    constructor(address payable _payment, address _token) {
        payment = APIPayment(_payment);
        token = IERC20(_token);
    }

    function prime(bytes memory _sig, uint256 _nonce, uint256 _validBeforeBlock, uint256 _ts) external {
        sig = _sig;
        nonce_ = _nonce;
        validBeforeBlock_ = _validBeforeBlock;
        ts_ = _ts;
    }

    function attackOnce() external {
        payment.withdraw(address(token), 1e6, nonce_, validBeforeBlock_, ts_, sig);
    }

    function reenter() external override {
        try payment.withdraw(address(token), 1e6, nonce_, validBeforeBlock_, ts_, sig) {
            revert("reenter should fail");
        } catch {}
    }
}

// ====== Main Tests ======

contract APIPaymentTest is Test {
    APIPayment payment;
    MockERC20 usdc;
    MockERC20 usdt;
    address owner = address(0x1);
    address signer;
    address alice = address(0x3);
    address[] emergencyAdmins;
    address[] tokens;

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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest); // private key 2 -> signer
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

        // Fund accounts
        usdc.mint(alice, 1_000_000e6);
        usdt.mint(alice, 1_000_000e6);

        // Setup admins
        emergencyAdmins = new address[](2);
        emergencyAdmins[0] = address(0x10);
        emergencyAdmins[1] = address(0x11);

        // Deploy contracts
        tokens = new address[](2);
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
            if (entries[i].topics.length > 0 && entries[i].topics[0] == expectedTopic) found = true;
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
            if (entries[i].topics.length > 0 && entries[i].topics[0] == expectedTopic) found = true;
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
        vm.stopPrank();
        assertEq(usdc.balanceOf(owner), before + 20e6);
    }

    /**
     * @notice Tests owner's ability to update the trusted signer
     * @dev Verifies old signatures become invalid after signer change
     */
    function testOwnerCanSetTrustedSigner() public {
        vm.startPrank(owner);
        address newSigner = vm.addr(55);
        payment.setTrustedSigner(newSigner);
        vm.stopPrank();

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

        bytes memory sigNew = abi.encodePacked(r, s, v);

        // Old signer signature should fail
        bytes memory sigOld = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sigOld);

        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sigNew);

        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        assertEq(usdc.balanceOf(address(payment)), 100e6 - amount);
        assertEq(payment.userNonce(alice), 1);
        vm.stopPrank();
    }

    function testSignerDisabledBlocksWithdraw() public {
        vm.prank(owner);
        payment.setTrustedSigner(address(0)); // Circuit breaker

        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);

        vm.expectRevert("Signer disabled");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
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
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;

        bytes memory sig1 = signWithdraw(alice, address(usdc), amount, 1, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sig1);

        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sig1);

        // Try with smaller nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, 0, validBeforeBlock, timestamp, sig1);

        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, 2, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, 2, validBeforeBlock, timestamp, sig2);
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
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sigAlice = signWithdraw(alice, address(usdc), amount, 1, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sigAlice);
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sigAlice);
        vm.stopPrank();

        vm.startPrank(bob);
        assertEq(payment.userNonce(bob), 0);
        bytes memory sigBob = signWithdraw(bob, address(usdc), amount, 1, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sigBob);
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
    
    function testReentrancyAttemptIsBlockedByNonce() public {
        // Malicious token + whitelist
        EvilERC20 evil = new EvilERC20(address(payment));
        vm.prank(owner);
        payment.setSupportedToken(address(evil), true);

        // Alice deposits
        evil.mint(alice, 10e6);
        vm.startPrank(alice);
        evil.approve(address(payment), 10e6);
        payment.deposit(10e6, address(evil));
        vm.stopPrank();

        // Attacker setup
        ReentrantAttack attacker = new ReentrantAttack(payable(address(payment)), address(evil));

        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(address(attacker), address(evil), 1e6, nonce, validBeforeBlock, timestamp);

        attacker.prime(sig, nonce, validBeforeBlock, timestamp);
        attacker.attackOnce(); // Attempts second withdraw in transfer callback

        assertEq(payment.userNonce(address(attacker)), 1);
        assertEq(evil.balanceOf(address(attacker)), 1e6);
    }

    /**
     * @notice Tests multi-sig pause mechanism
     * @dev Requires 2/3 majority of emergency admins to pause
     */
    function testPauseByMajorityAdmin() public {
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Paused too early");

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

        // OZ v5 Pausable custom error selector
        vm.expectRevert(bytes4(keccak256("EnforcedPause()")));
        payment.deposit(100e6, address(usdc));

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);

        vm.expectRevert(bytes4(keccak256("EnforcedPause()")));
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    function testInsufficientVaultReverts() public {
        // Alice deposits
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        vm.stopPrank();

        // Owner empties the vault
        vm.prank(owner);
        payment.transferTo(address(usdc), owner, 100e6);

        // Withdrawal should fail
        vm.startPrank(alice);
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        vm.expectRevert("Insufficient vault");
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

    function testEvent_UnpausedByVote_Emitted() public {
        // First achieve pause state
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "precondition: paused");

        // Expected: voteUnpause by 0x11 triggers UnpausedByVote(admin=0x11, votes=1)
        vm.recordLogs();
        vm.prank(address(0x11));
        payment.voteUnpause();

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic0 = keccak256("UnpausedByVote(address,uint256)");
        bytes32 expAdmin = bytes32(uint256(uint160(address(0x11)))); // indexed address -> topic1
        bool found;

        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(payment) && logs[i].topics.length >= 2 && logs[i].topics[0] == topic0
                    && logs[i].topics[1] == expAdmin
            ) {
                // data contains votes(uint256)
                (uint256 votes) = abi.decode(logs[i].data, (uint256));
                assertEq(votes, 1, "votes");
                found = true;
                break;
            }
        }
        assertTrue(found, "UnpausedByVote not found");
    }

    function testEvent_TrustedSignerUpdated_Emitted() public {
        address oldSigner = signer; // Set in setUp as vm.addr(2)
        address newSigner = vm.addr(77);

        vm.recordLogs();
        vm.prank(owner);
        payment.setTrustedSigner(newSigner);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic0 = keccak256("TrustedSignerUpdated(address,address)");
        bytes32 expOld = bytes32(uint256(uint160(oldSigner)));
        bytes32 expNew = bytes32(uint256(uint160(newSigner)));
        bool found;

        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(payment) && logs[i].topics.length == 3 && logs[i].topics[0] == topic0
                    && logs[i].topics[1] == expOld && logs[i].topics[2] == expNew
            ) {
                // Both event parameters are indexed, data is empty
                assertEq(logs[i].data.length, 0, "data should be empty");
                found = true;
                break;
            }
        }
        assertTrue(found, "TrustedSignerUpdated not found");
    }

    function testEvent_SupportedTokenUpdated_AddEmitted() public {
        // Add a token not whitelisted in constructor
        MockERC20 fake = new MockERC20("FAKE", "FAKE");

        vm.recordLogs();
        vm.prank(owner);
        payment.setSupportedToken(address(fake), true);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic0 = keccak256("SupportedTokenUpdated(address,bool)");
        bytes32 expToken = bytes32(uint256(uint160(address(fake))));
        bool found;

        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(payment) && logs[i].topics.length >= 2 && logs[i].topics[0] == topic0
                    && logs[i].topics[1] == expToken
            ) {
                // data contains bool isSupported
                (bool isSupported) = abi.decode(logs[i].data, (bool));
                assertTrue(isSupported, "isSupported should be true");
                found = true;
                break;
            }
        }
        assertTrue(found, "SupportedTokenUpdated(add) not found");
        assertTrue(payment.supportedTokens(address(fake)), "state not updated");
    }

    function testEvent_SupportedTokenUpdated_RemoveEmitted() public {
        // Constructor already supports usdc; remove it here
        assertTrue(payment.supportedTokens(address(usdc)), "precondition failed");

        vm.recordLogs();
        vm.prank(owner);
        payment.setSupportedToken(address(usdc), false);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic0 = keccak256("SupportedTokenUpdated(address,bool)");
        bytes32 expToken = bytes32(uint256(uint160(address(usdc))));
        bool found;

        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(payment) && logs[i].topics.length >= 2 && logs[i].topics[0] == topic0
                    && logs[i].topics[1] == expToken
            ) {
                (bool isSupported) = abi.decode(logs[i].data, (bool));
                assertFalse(isSupported, "isSupported should be false");
                found = true;
                break;
            }
        }
        assertTrue(found, "SupportedTokenUpdated(remove) not found");
        assertFalse(payment.supportedTokens(address(usdc)), "state not updated");
    }
}
