// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/APIPayment.sol";
import "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

// 简单Mock Token实现
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

    function setUp() public {
        usdc = new MockERC20("USDC", "USDC");
        usdt = new MockERC20("USDT", "USDT");

        signer = vm.addr(2);

        // fund alice account
        usdc.mint(alice, 1_000_000e6);
        usdt.mint(alice, 1_000_000e6);

        // depoly
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdt);

        payment = new APIPayment(tokens, signer, owner);
    }

    function testDepositAndWithdraw() public {
        vm.startPrank(alice);

        // approve 合约
        usdc.approve(address(payment), 100e6);

        // deposit
        payment.deposit(100e6, address(usdc));
        assertEq(usdc.balanceOf(address(payment)), 100e6);

        // 链下生成withdraw签名，链上claim
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        bytes32 structHash =
            keccak256(abi.encode(payment.WITHDRAW_TYPEHASH(), alice, address(usdc), amount, nonce, validBeforeBlock));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", payment.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // console.logBytes32(structHash);
        // console.logBytes32(digest);
        // console.logBytes32(payment.WITHDRAW_TYPEHASH());

        // withdraw
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig);

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
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock);

        vm.recordLogs();
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool found = false;
        bytes32 expectedTopic = keccak256("Withdraw(address,address,uint256,uint256)");
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
        // 不能直接assert private var，需额外getter或事件，可测试无revert
        // 测试用这个的私钥可以成功提现
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        assertEq(usdc.balanceOf(alice), 1_000_000e6 - 100e6);

        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        bytes32 structHash =
            keccak256(abi.encode(payment.WITHDRAW_TYPEHASH(), alice, address(usdc), amount, nonce, validBeforeBlock));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", payment.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(55, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig2);

        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig);

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
        bytes memory sig = signWithdraw(alice, address(fakeToken), amount, nonce, validBeforeBlock);

        vm.startPrank(alice);
        vm.expectRevert("Token not supported");
        payment.withdraw(address(fakeToken), amount, nonce, validBeforeBlock, sig);
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
        bytes memory sig1 = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig1);

        // 再次用同样nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig1);

        // 用更小的nonce
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce - 1, validBeforeBlock, sig1);

        // 用更大的nonce
        uint256 nonce2 = 2;
        bytes memory sig2 = signWithdraw(alice, address(usdc), amount, nonce2, validBeforeBlock);
        payment.withdraw(address(usdc), amount, nonce2, validBeforeBlock, sig2);
        vm.stopPrank();
    }

    function testWithdrawBlockExpired() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 1;
        bytes memory sig = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock);
        vm.roll(validBeforeBlock + 1); // 跳区块
        vm.expectRevert("Signature expired");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig);
        vm.stopPrank();
    }

    function testWithdrawInvalidSignature() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        // 用错误的私钥签名
        bytes32 structHash =
            keccak256(abi.encode(payment.WITHDRAW_TYPEHASH(), alice, address(usdc), amount, nonce, validBeforeBlock));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", payment.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(99, digest); // 错误私钥
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig);
        vm.stopPrank();
    }

    function testWithdrawWrongReceiver() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;

        // 用bob地址构造签名
        address bob = address(0xB0B);
        bytes32 structHash =
            keccak256(abi.encode(payment.WITHDRAW_TYPEHASH(), bob, address(usdc), amount, nonce, validBeforeBlock));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", payment.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest); // 签名没问题
        bytes memory sig = abi.encodePacked(r, s, v);

        // alice用bob的签名去提（不通过，因为msg.sender!=bob）
        vm.expectRevert("Invalid signature"); // 或"Invalid nonce"
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sig);
        vm.stopPrank();
    }

    function testWithdrawNoncePerUser() public {
        address bob = address(0xB0B);

        // bob充值
        usdc.mint(bob, 100e6);
        vm.startPrank(bob);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        vm.stopPrank();

        // alice充值
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));
        // alice nonce=1
        uint256 amount = 10e6;
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        bytes memory sigAlice = signWithdraw(alice, address(usdc), amount, nonce, validBeforeBlock);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sigAlice);

        // alice再用nonce=1
        vm.expectRevert("Invalid nonce");
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sigAlice);
        vm.stopPrank();

        // bob也用nonce=1（自己的）
        vm.startPrank(bob);
        assertEq(payment.userNonce(bob), 0);
        bytes memory sigBob = signWithdraw(bob, address(usdc), amount, nonce, validBeforeBlock);
        payment.withdraw(address(usdc), amount, nonce, validBeforeBlock, sigBob);
        assertEq(payment.userNonce(bob), 1);
        vm.stopPrank();
    }

    function testWithdrawInvalidAmountSignature() public {
        vm.startPrank(alice);
        usdc.approve(address(payment), 100e6);
        payment.deposit(100e6, address(usdc));

        uint256 correctAmount = 10e6;
        uint256 wrongAmount = 11e6; // 实际要提取的错误金额
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;

        // 用正确参数签名
        bytes memory sig = signWithdraw(alice, address(usdc), correctAmount, nonce, validBeforeBlock);

        // 用错误的amount参数去提现（应该revert）
        vm.expectRevert("Invalid signature");
        payment.withdraw(address(usdc), wrongAmount, nonce, validBeforeBlock, sig);

        vm.stopPrank();
    }

    function testNoReentrancy() public {
        // 部署攻击合约
        ReentrantAttack attacker = new ReentrantAttack(address(payment), address(usdc));

        // 设置环境
        vm.startPrank(alice);
        usdc.approve(address(payment), 10e6);
        payment.deposit(10e6, address(usdc));
        usdc.transfer(address(attacker), 10e6);
        vm.stopPrank();

        // 正常签名
        uint256 nonce = 1;
        uint256 validBeforeBlock = block.number + 100;
        bytes memory sig = signWithdraw(address(attacker), address(usdc), 1e6, nonce, validBeforeBlock);

        // 攻击
        // 只要withdraw先更新nonce，reentry时会被nonce拦截，攻击失败
        attacker.attack(sig, nonce, validBeforeBlock);

        // 检查
        assertEq(payment.userNonce(address(attacker)), 1);
        assertEq(usdc.balanceOf(address(attacker)), 11e6);
    }

    function signWithdraw(address user, address token, uint256 amount, uint256 nonce, uint256 validBeforeBlock)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(payment.WITHDRAW_TYPEHASH(), user, token, amount, nonce, validBeforeBlock));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", payment.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        return abi.encodePacked(r, s, v);
    }
}

// 重入攻击合约
contract ReentrantAttack {
    APIPayment public payment;
    IERC20 public usdc;
    address public attacker;
    bytes public lastSig;
    uint256 public lastNonce;
    uint256 public lastBlock;

    constructor(address _payment, address _usdc) {
        payment = APIPayment(_payment);
        usdc = IERC20(_usdc);
        attacker = msg.sender;
    }

    // 重入发生在 receive hook
    function attack(bytes memory sig, uint256 nonce, uint256 validBeforeBlock) public {
        lastSig = sig;
        lastNonce = nonce;
        lastBlock = validBeforeBlock;
        payment.withdraw(address(usdc), 1e6, nonce, validBeforeBlock, sig);
    }

    // fallback，尝试重入
    receive() external payable {
        // 在这里再次调用 withdraw
        // 只要nonce更新在转账前，这里会revert
        try payment.withdraw(address(usdc), 1e6, lastNonce, lastBlock, lastSig) {
            revert("Should not succeed");
        } catch {}
    }
}
