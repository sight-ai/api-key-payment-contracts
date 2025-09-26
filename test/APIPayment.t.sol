// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/APIPayment.sol";
import "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

// ====== 测试辅助合约 ======

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    function mint(address to, uint256 amount) public { _mint(to, amount); }
}

interface IReenter { function reenter() external; }

contract EvilERC20 is ERC20 {
    address public immutable payment;

    constructor(address _payment) ERC20("EVIL", "EVIL") {
        payment = _payment;
    }

    function mint(address to, uint256 amount) public { _mint(to, amount); }

    // ✅ OZ v5 写法：统一的内部钩子
    function _update(address from, address to, uint256 value) internal override {
        // 先执行余额更新
        super._update(from, to, value);

        // 当从 APIPayment 转出到“合约地址”时，尝试回调触发重入
        if (from == payment && to.code.length > 0) {
            try IReenter(to).reenter() { } catch { }
        }
    }
}

// 尝试在代币转账回调期间二次调用 withdraw（应被 nonce 限制挡住）
contract ReentrantAttack is IReenter {
    APIPayment public payment;
    IERC20 public token;

    bytes public sig;
    uint256 public nonce_;
    uint256 public validBeforeBlock_;
    uint256 public ts_;

    // 🔧 这里需要 address payable（因为 APIPayment 有 payable fallback）
    constructor(address payable _payment, address _token) {
        payment = APIPayment(_payment);
        token = IERC20(_token);
    }

    function prime(bytes memory _sig, uint256 _nonce, uint256 _validBeforeBlock, uint256 _ts) external {
        sig = _sig; nonce_ = _nonce; validBeforeBlock_ = _validBeforeBlock; ts_ = _ts;
    }

    function attackOnce() external {
        payment.withdraw(address(token), 1e6, nonce_, validBeforeBlock_, ts_, sig);
    }

    function reenter() external override {
        try payment.withdraw(address(token), 1e6, nonce_, validBeforeBlock_, ts_, sig) {
            revert("reenter should fail");
        } catch { }
    }
}


// ====== 主测试 ======

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

    // 手动拼 EIP712 域（与合约 _hashTypedDataV4 对齐）
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest); // 私钥2 -> signer
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        usdc = new MockERC20("USDC", "USDC");
        usdt = new MockERC20("USDT", "USDT");
        signer = vm.addr(2);

        // 资金
        usdc.mint(alice, 1_000_000e6);
        usdt.mint(alice, 1_000_000e6);

        // 管理员
        emergencyAdmins = new address[](2);
        emergencyAdmins[0] = address(0x10);
        emergencyAdmins[1] = address(0x11);

        // 部署
        tokens = new address[](2);
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
            if (entries[i].topics.length > 0 && entries[i].topics[0] == expectedTopic) found = true;
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
            if (entries[i].topics.length > 0 && entries[i].topics[0] == expectedTopic) found = true;
        }
        assertTrue(found, "Withdraw event not found!");
        vm.stopPrank();
    }

    function testOwnerCanTransferTo() public {
        usdc.mint(address(payment), 100e6);
        uint256 before = usdc.balanceOf(owner);
        vm.startPrank(owner);
        payment.transferTo(address(usdc), owner, 20e6);
        vm.stopPrank();
        assertEq(usdc.balanceOf(owner), before + 20e6);
    }

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

        // 新 signer 签名
        bytes32 typehash = payment.WITHDRAW_TYPEHASH();
        bytes32 structHash =
            keccak256(abi.encode(typehash, alice, address(usdc), amount, nonce, validBeforeBlock, timestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(55, digest);
        bytes memory sigNew = abi.encodePacked(r, s, v);

        // 旧 signer 签名应失败
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
        payment.setTrustedSigner(address(0)); // 熔断

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

        uint256 amount = 10e6;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;

        bytes memory sig1 = signWithdraw(alice, address(usdc), amount, 1, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sig1);

        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, 1, validBeforeBlock, timestamp, sig1);

        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, 0, validBeforeBlock, timestamp, sig1);

        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, 2, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, 2, validBeforeBlock, timestamp, sig2);
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
        vm.roll(validBeforeBlock + 1); // 越过有效区块
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

        // 用错误私钥签
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
        // 恶意代币 + 白名单
        EvilERC20 evil = new EvilERC20(address(payment));
        vm.prank(owner);
        payment.setSupportedToken(address(evil), true);

        // Alice 入金
        evil.mint(alice, 10e6);
        vm.startPrank(alice);
        evil.approve(address(payment), 10e6);
        payment.deposit(10e6, address(evil));
        vm.stopPrank();

        // 攻击者
        ReentrantAttack attacker = new ReentrantAttack(payable(address(payment)), address(evil));

        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(address(attacker), address(evil), 1e6, nonce, validBeforeBlock, timestamp);

        attacker.prime(sig, nonce, validBeforeBlock, timestamp);
        attacker.attackOnce(); // 在转账回调中尝试二次 withdraw

        assertEq(payment.userNonce(address(attacker)), 1);
        assertEq(evil.balanceOf(address(attacker)), 1e6);
    }

    function testPauseByMajorityAdmin() public {
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Paused too early");

        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused after 2 votes");
    }

    function testPauseNotEnoughVotes() public {
        vm.prank(address(0x10));
        payment.votePause();
        assertFalse(payment.paused(), "Should NOT be paused with only one vote");
    }

    function testUnpauseByAdmin() public {
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused now");

        vm.prank(address(0x11));
        payment.voteUnpause();
        assertFalse(payment.paused(), "Should be unpaused when votes < 2/3");
    }

    function testPauseDisablesDepositAndWithdraw() public {
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "Should be paused");

        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);

        // OZ v5 Pausable 自定义错误选择器
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
        // Alice 入金
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        vm.stopPrank();

        // Owner 转空金库
        vm.prank(owner);
        payment.transferTo(address(usdc), owner, 100e6);

        // 再提现失败
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

    function testEIP712TypedDataSignatureWorks() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        uint256 timestamp = block.timestamp;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock, timestamp);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, timestamp, sig);
        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6 + amount);
        vm.stopPrank();
    }
    function testEvent_UnpausedByVote_Emitted() public {
        // 先达到暂停
        vm.prank(address(0x10));
        payment.votePause();
        vm.prank(address(0x11));
        payment.votePause();
        assertTrue(payment.paused(), "precondition: paused");

        // 期望：由 0x11 发起的 voteUnpause 触发 UnpausedByVote(admin=0x11, votes=1)
        vm.recordLogs();
        vm.prank(address(0x11));
        payment.voteUnpause();

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic0 = keccak256("UnpausedByVote(address,uint256)");
        bytes32 expAdmin = bytes32(uint256(uint160(address(0x11)))); // indexed address -> topic1
        bool found;

        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(payment) &&
                logs[i].topics.length >= 2 &&
                logs[i].topics[0] == topic0 &&
                logs[i].topics[1] == expAdmin
            ) {
                // data 里是 votes(uint256)
                (uint256 votes) = abi.decode(logs[i].data, (uint256));
                assertEq(votes, 1, "votes");
                found = true;
                break;
            }
        }
        assertTrue(found, "UnpausedByVote not found");
    }

    function testEvent_TrustedSignerUpdated_Emitted() public {
        address oldSigner = signer;           // setUp 里设置的 vm.addr(2)
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
                logs[i].emitter == address(payment) &&
                logs[i].topics.length == 3 &&
                logs[i].topics[0] == topic0 &&
                logs[i].topics[1] == expOld &&
                logs[i].topics[2] == expNew
            ) {
                // 该事件两个参数都 indexed，data 为空
                assertEq(logs[i].data.length, 0, "data should be empty");
                found = true;
                break;
            }
        }
        assertTrue(found, "TrustedSignerUpdated not found");
    }

    function testEvent_SupportedTokenUpdated_AddEmitted() public {
        // 新增一个未在构造器里白名单的 token
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
                logs[i].emitter == address(payment) &&
                logs[i].topics.length >= 2 &&
                logs[i].topics[0] == topic0 &&
                logs[i].topics[1] == expToken
            ) {
                // data 里是 bool isSupported
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
        // 构造器默认已支持 usdc；这里将其移除
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
                logs[i].emitter == address(payment) &&
                logs[i].topics.length >= 2 &&
                logs[i].topics[0] == topic0 &&
                logs[i].topics[1] == expToken
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