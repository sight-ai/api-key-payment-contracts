// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/APIPayment.sol";
import "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

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

    // 测试手动拼 EIP，合约内部是_hashTypedDataV4
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

    function testOwnerCanTransferTo() public {
        usdc.mint(address(payment), 100e6);
        uint256 before = usdc.balanceOf(owner);
        vm.startPrank(owner);
        payment.transferTo(address(usdc), owner, 20e6);
        assertEq(usdc.balanceOf(owner), before + 20e6);
        vm.stopPrank();
    }

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

        // 用新signer签名
        bytes32 typehash = payment.WITHDRAW_TYPEHASH();
        bytes32 structHash =
            keccak256(abi.encode(typehash, alice, address(usdc), amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(55, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // 用旧signer签名应该失败
        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig2);

        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);

        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        assertEq(usdc.balanceOf(address(payment)), 100e6 - amount);
        assertEq(payment.userNonce(alice), 1);

        vm.stopPrank();
    }

    function testDepositNotSupportedTokenReverts() public {
        MockERC20 fakeToken = new MockERC20("FAKE", "FAKE");
        fakeToken.mint(alice, 100e6);
        vm.startPrank(alice);
        fakeToken.approve(address(payment), 100e6);
        vm.expectRevert("Token not supported");
        payment.deposit(100e6, address(fakeToken));
        vm.stopPrank();
    }

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

    function testWithdrawNonceChecks() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        // 第一次提现
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig1 = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig1);

        // 再次用同样nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig1);

        // 用更小的nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce - 1, validBeforeBlock, timestamp, sig1);

        // 用更大的nonce
        uint256 nonce2 = 2;
        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, nonce2, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce2, validBeforeBlock, timestamp, sig2);
        vm.stopPrank();
    }

    function testWithdrawBlockExpired() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 1;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        vm.roll(validBeforeBlock + 1); // 跳区块
        vm.expectRevert("Signature expired");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        vm.stopPrank();
    }

    function testWithdrawInvalidSignature() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        // 用错误的私钥签名
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

    function testPauseByMajorityAdmin() public {
        // 两个emergencyAdmins, 2/3 规则即都同意才可pause
        // 1号投票
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Paused too early");
        // 2号投票
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused after 2 votes");
    }

    function testPauseNotEnoughVotes() public {
        // 只有一个admin投票，不足多数，不能pause
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Should NOT be paused with only one vote");
    }

    function testUnpauseByAdmin() public {
        // 两票pause
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused now");

        // 取消1票, 应可unpause
        vm.prank(address(0x11));
        payment.voteUnpause();
        assertFalse(payment.paused(), "Should be unpaused when votes < 2/3");
    }

    function testPauseDisablesDepositAndWithdraw() public {
        // 两票pause
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

    // 测试切换到_hashTypedDataV4后，合约正确工作
    function testEIP712TypedDataSignatureWorks() public {
        // 测试EIP712切换后签名有效
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        // 用主流程 signWithdraw 即为EIP712格式
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        vm.stopPrank();
    }
}

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
