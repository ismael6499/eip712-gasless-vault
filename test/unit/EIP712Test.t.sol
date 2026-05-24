// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {PermitToken} from "../../src/PermitToken.sol";
import {GaslessVault} from "../../src/GaslessVault.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @title EIP712Test — Comprehensive tests for EIP-712 Typed Structured Data Signing
/// @notice These tests demonstrate the FULL EIP-712 signing flow step by step,
/// using OpenZeppelin's ERC20Permit, EIP712, ECDSA, and Nonces.
///
/// HOW FOUNDRY SIGNING WORKS:
///   - vm.sign(privateKey, digest) → returns (v, r, s)
///   - The private key is a uint256, and we derive the address from it
///   - This simulates what MetaMask / hardware wallets do off-chain
///
contract EIP712Test is Test {
    // ─── Contracts ───────────────────────────────
    PermitToken token;
    GaslessVault vault;

    // ─── Actors ──────────────────────────────────
    // We use private keys so we can sign messages with vm.sign()
    uint256 constant ALICE_PK = 0xA11CE;
    address ALICE;

    uint256 constant BOB_PK = 0xB0B;
    address BOB;

    address RELAYER = makeAddr("relayer");
    address OWNER = makeAddr("owner");

    // ─── Constants ───────────────────────────────
    uint256 constant INITIAL_SUPPLY = 1_000_000e18;
    uint256 constant ALICE_AMOUNT = 10_000e18;

    /// @dev The EIP-712 Permit typehash (same constant OZ uses internally)
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // ─── Setup ───────────────────────────────────
    function setUp() public {
        // Derive addresses from private keys
        ALICE = vm.addr(ALICE_PK);
        BOB = vm.addr(BOB_PK);

        // Deploy contracts as OWNER
        vm.startPrank(OWNER);
        token = new PermitToken("PermitToken", "PTK", INITIAL_SUPPLY);
        vault = new GaslessVault(token);

        // Fund Alice with tokens
        token.transfer(ALICE, ALICE_AMOUNT);
        vm.stopPrank();
    }

    // ═════════════════════════════════════════════════════════════════════
    // 1: EIP-712 FUNDAMENTALS
    // ═════════════════════════════════════════════════════════════════════
    // These tests verify that the EIP-712 building blocks are correct.
    // Developers: Read these to understand HOW the domain separator and
    // type hashes are constructed.

    /// @notice Verify the domain separator is computed correctly from its components
    /// @dev This test reconstructs the domain separator manually to show
    /// exactly what goes into it.
    function test_domainSeparatorComputedCorrectly() public view {
        // Manually compute what the domain separator SHOULD be
        bytes32 domainTypeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

        bytes32 expected = keccak256(
            abi.encode(
                domainTypeHash,
                keccak256("PermitToken"), // name hash
                keccak256("1"), //           version hash
                block.chainid, //            chain ID
                address(token) //            contract address
            )
        );

        assertEq(token.DOMAIN_SEPARATOR(), expected, "Domain separator mismatch");
    }

    /// @notice Each contract has its OWN domain separator (different addresses!)
    /// @dev This is KEY to understanding why EIP-712 prevents cross-contract replay.
    function test_tokenAndVaultHaveDifferentDomainSeparators() public view {
        // The token's domain separator uses name="PermitToken" and address(token)
        // The vault's domain separator uses name="GaslessVault" and address(vault)
        // They are DIFFERENT, so signatures cannot be replayed across them
        assertTrue(
            token.DOMAIN_SEPARATOR() != vault.DOMAIN_SEPARATOR(),
            "Token and vault should have different domain separators"
        );
    }

    /// @notice Verify the PERMIT_TYPEHASH matches the canonical type string
    /// @dev OZ makes PERMIT_TYPEHASH private, so we verify by computing it ourselves
    function test_permitTypehashMatchesExpected() public pure {
        bytes32 expected = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );
        assertEq(PERMIT_TYPEHASH, expected);
    }

    /// @notice Verify the WITHDRAW_TYPEHASH matches the canonical type string
    function test_withdrawTypehashMatchesExpected() public view {
        bytes32 expected = keccak256(
            "WithdrawAuthorization(address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)"
        );
        assertEq(vault.WITHDRAW_TYPEHASH(), expected);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 2: ERC-2612 PERMIT — Gasless Approvals
    // ═════════════════════════════════════════════════════════════════════
    // The most common use of EIP-712: approving token spending via signature.

    /// @notice Full permit flow: Alice signs off-chain, anyone submits on-chain
    /// @dev This test walks through the COMPLETE EIP-712 signing process.
    function test_permitSetsAllowance() public {
        uint256 amount = 1000e18;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = token.nonces(ALICE); // should be 0

        // ── STEP 1: Build the struct hash (what Alice is signing) ──
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                ALICE, //           owner
                address(vault), //  spender
                amount, //          value
                nonce, //           nonce (0)
                deadline //         deadline
            )
        );

        // ── STEP 2: Build the full EIP-712 digest ──
        // digest = keccak256("\x19\x01" || domainSeparator || structHash)
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash)
        );

        // ── STEP 3: Alice signs the digest with her private key ──
        // In the real world, MetaMask does this via eth_signTypedData_v4
        // In Foundry, we use vm.sign(privateKey, digest)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);

        // ── STEP 4: Anyone (here: RELAYER) submits the signature on-chain ──
        // Alice doesn't need to send a transaction or pay gas!
        vm.prank(RELAYER);
        token.permit(ALICE, address(vault), amount, deadline, v, r, s);

        // ── VERIFY: Allowance is now set ──
        assertEq(token.allowance(ALICE, address(vault)), amount);
    }

    /// @notice Permit increments the nonce to prevent replay
    function test_permitIncrementsNonce() public {
        uint256 nonceBefore = token.nonces(ALICE);

        // Sign and submit a permit
        _signAndSubmitPermit(ALICE, ALICE_PK, address(vault), 100e18, block.timestamp + 1 hours);

        uint256 nonceAfter = token.nonces(ALICE);
        assertEq(nonceAfter, nonceBefore + 1, "Nonce should increment by 1");
    }

    /// @notice Permit reverts if deadline has passed
    function test_permitRevertsAfterDeadline() public {
        uint256 deadline = block.timestamp + 1 hours;

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), 100e18, 0, deadline
        );

        // Warp past the deadline
        vm.warp(deadline + 1);

        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, deadline));
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);
    }

    /// @notice Permit reverts if someone forges a signature
    function test_permitRevertsWithWrongSigner() public {
        uint256 deadline = block.timestamp + 1 hours;

        // BOB signs a permit claiming to be ALICE
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, BOB_PK, address(vault), 100e18, 0, deadline // BOB's PK but ALICE as owner!
        );

        // OZ recovers BOB's address and reverts because BOB != ALICE
        vm.expectRevert(
            abi.encodeWithSelector(ERC20Permit.ERC2612InvalidSigner.selector, vm.addr(BOB_PK), ALICE)
        );
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);
    }

    /// @notice Same signature cannot be used twice (nonce prevents replay)
    function test_permitRevertsWithReusedSignature() public {
        uint256 deadline = block.timestamp + 1 hours;

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), 100e18, 0, deadline
        );

        // First use — succeeds
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);

        // Second use — reverts (nonce is now 1, but signature was for nonce 0)
        // OZ ECDSA.recover will produce a different address since the structHash
        // is different (nonce 0 vs nonce 1), so we get ERC2612InvalidSigner
        vm.expectRevert();
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 3: GASLESS VAULT DEPOSITS
    // ═════════════════════════════════════════════════════════════════════
    // Combining Permit + deposit in one transaction via a relayer.

    /// @notice Full gasless deposit: Alice signs, relayer submits
    function test_depositWithPermitViaRelayer() public {
        uint256 amount = 500e18;
        uint256 deadline = block.timestamp + 1 hours;

        // Alice signs a permit for the vault to spend her tokens
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), amount, 0, deadline
        );

        // Relayer calls depositWithPermit — Alice pays no gas!
        vm.prank(RELAYER);
        vault.depositWithPermit(ALICE, amount, deadline, v, r, s);

        // Verify: vault has Alice's tokens
        assertEq(vault.vaultBalanceOf(ALICE), amount);
        assertEq(token.balanceOf(ALICE), ALICE_AMOUNT - amount);
    }

    /// @notice Multiple deposits accumulate in vault balance
    function test_multipleDepositsAccumulate() public {
        uint256 amount1 = 200e18;
        uint256 amount2 = 300e18;
        uint256 deadline = block.timestamp + 1 hours;

        // First deposit
        (uint8 v1, bytes32 r1, bytes32 s1) = _signPermit(
            ALICE, ALICE_PK, address(vault), amount1, 0, deadline
        );
        vault.depositWithPermit(ALICE, amount1, deadline, v1, r1, s1);

        // Second deposit (nonce is now 1)
        (uint8 v2, bytes32 r2, bytes32 s2) = _signPermit(
            ALICE, ALICE_PK, address(vault), amount2, 1, deadline
        );
        vault.depositWithPermit(ALICE, amount2, deadline, v2, r2, s2);

        assertEq(vault.vaultBalanceOf(ALICE), amount1 + amount2);
    }

    /// @notice depositWithPermit reverts with zero amount
    function test_depositRevertsWithZeroAmount() public {
        uint256 deadline = block.timestamp + 1 hours;

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), 0, 0, deadline
        );

        vm.expectRevert(GaslessVault.ZeroAmount.selector);
        vault.depositWithPermit(ALICE, 0, deadline, v, r, s);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 4: GASLESS VAULT WITHDRAWALS (Custom EIP-712 Struct)
    // ═════════════════════════════════════════════════════════════════════
    // This section uses a DIFFERENT EIP-712 struct: WithdrawAuthorization.

    /// @notice Full gasless withdrawal: Alice signs, relayer submits
    function test_withdrawBySigTransfersTokens() public {
        uint256 depositAmount = 500e18;
        uint256 withdrawAmount = 200e18;
        uint256 deadline = block.timestamp + 1 hours;

        // Setup: deposit tokens into vault first
        _depositToVault(ALICE, ALICE_PK, depositAmount);

        // Alice signs a WithdrawAuthorization (custom EIP-712 struct!)
        (uint8 v, bytes32 r, bytes32 s) = _signWithdraw(
            ALICE, ALICE_PK, BOB, withdrawAmount, 0, deadline
        );

        // Relayer submits the withdrawal
        vm.prank(RELAYER);
        vault.withdrawBySig(ALICE, BOB, withdrawAmount, deadline, v, r, s);

        // Verify
        assertEq(vault.vaultBalanceOf(ALICE), depositAmount - withdrawAmount);
        assertEq(token.balanceOf(BOB), withdrawAmount);
    }

    /// @notice Withdrawal nonce increments after each use
    function test_withdrawBySigIncrementsNonce() public {
        _depositToVault(ALICE, ALICE_PK, 500e18);

        uint256 nonceBefore = vault.nonces(ALICE);

        (uint8 v, bytes32 r, bytes32 s) = _signWithdraw(
            ALICE, ALICE_PK, BOB, 100e18, 0, block.timestamp + 1 hours
        );
        vault.withdrawBySig(ALICE, BOB, 100e18, block.timestamp + 1 hours, v, r, s);

        assertEq(vault.nonces(ALICE), nonceBefore + 1);
    }

    /// @notice Withdrawal reverts after deadline
    function test_withdrawBySigRevertsAfterDeadline() public {
        _depositToVault(ALICE, ALICE_PK, 500e18);
        uint256 deadline = block.timestamp + 1 hours;

        (uint8 v, bytes32 r, bytes32 s) = _signWithdraw(
            ALICE, ALICE_PK, BOB, 100e18, 0, deadline
        );

        vm.warp(deadline + 1);

        vm.expectRevert(GaslessVault.DeadlineExpired.selector);
        vault.withdrawBySig(ALICE, BOB, 100e18, deadline, v, r, s);
    }

    /// @notice Withdrawal reverts with wrong signer
    function test_withdrawBySigRevertsWithWrongSigner() public {
        _depositToVault(ALICE, ALICE_PK, 500e18);
        uint256 deadline = block.timestamp + 1 hours;

        // BOB signs but claims to be ALICE
        (uint8 v, bytes32 r, bytes32 s) = _signWithdraw(
            ALICE, BOB_PK, BOB, 100e18, 0, deadline
        );

        vm.expectRevert(GaslessVault.InvalidWithdrawSignature.selector);
        vault.withdrawBySig(ALICE, BOB, 100e18, deadline, v, r, s);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 5: SECURITY — Replay & Cross-Contract Protection
    // ═════════════════════════════════════════════════════════════════════

    /// @notice Permit signature cannot be replayed after nonce increment
    function test_replayBlockedByNonce() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Alice permits 100 tokens
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), 100e18, 0, deadline
        );
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);

        // Try to replay — fails because nonce is now 1
        vm.expectRevert();
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);
    }

    /// @notice A permit signature for token A cannot work on token B
    function test_signatureNotReplayableAcrossContracts() public {
        // Deploy a second token with the SAME name (evil clone)
        vm.prank(OWNER);
        PermitToken evilToken = new PermitToken("PermitToken", "EVIL", INITIAL_SUPPLY);

        uint256 deadline = block.timestamp + 1 hours;

        // Sign a permit for the ORIGINAL token
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), 100e18, 0, deadline
        );

        // Try to use it on the evil token — fails because address(this) differs
        // in the domain separator, even though the name is the same!
        vm.expectRevert();
        evilToken.permit(ALICE, address(vault), 100e18, deadline, v, r, s);
    }

    /// @notice A withdraw signature cannot be replayed as a permit
    function test_withdrawSigCannotBeUsedAsPermit() public {
        _depositToVault(ALICE, ALICE_PK, 500e18);
        uint256 deadline = block.timestamp + 1 hours;

        // Sign a withdrawal authorization
        (uint8 v, bytes32 r, bytes32 s) = _signWithdraw(
            ALICE, ALICE_PK, BOB, 100e18, 0, deadline
        );

        // Try to use it as a permit — different struct hash + different domain separator
        vm.expectRevert();
        token.permit(ALICE, BOB, 100e18, deadline, v, r, s);
    }

    /// @notice Withdrawal reverts when vault balance is insufficient
    function test_withdrawRevertsOnInsufficientBalance() public {
        _depositToVault(ALICE, ALICE_PK, 100e18);
        uint256 deadline = block.timestamp + 1 hours;

        // Try to withdraw more than deposited
        (uint8 v, bytes32 r, bytes32 s) = _signWithdraw(
            ALICE, ALICE_PK, BOB, 200e18, 0, deadline
        );

        vm.expectRevert(GaslessVault.InsufficientVaultBalance.selector);
        vault.withdrawBySig(ALICE, BOB, 200e18, deadline, v, r, s);
    }

    // ═════════════════════════════════════════════════════════════════════
    // 6: FUZZ TESTS
    // ═════════════════════════════════════════════════════════════════════

    /// @notice Fuzz: random private keys always fail to forge permits for Alice
    function test_fuzz_randomSignerCannotForgePermit(uint256 randomPk) public {
        // Bound to valid private key range (1 to secp256k1 order - 1)
        randomPk = bound(randomPk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);

        // Skip if the random key happens to be Alice's key
        vm.assume(randomPk != ALICE_PK);

        uint256 deadline = block.timestamp + 1 hours;

        // Sign with a random private key, claiming to be Alice
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, randomPk, address(vault), 100e18, 0, deadline
        );

        // Should ALWAYS revert — only Alice's private key can sign for Alice
        // OZ will revert with ERC2612InvalidSigner(recoveredAddr, ALICE)
        vm.expectRevert();
        token.permit(ALICE, address(vault), 100e18, deadline, v, r, s);
    }

    /// @notice Fuzz: permit works for any valid amount and deadline
    function test_fuzz_permitWorksForAnyAmountAndDeadline(uint256 amount, uint256 deadline) public {
        deadline = bound(deadline, block.timestamp, type(uint256).max);
        // Amount can be anything (even more than balance — permit just sets allowance)

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            ALICE, ALICE_PK, address(vault), amount, 0, deadline
        );

        token.permit(ALICE, address(vault), amount, deadline, v, r, s);
        assertEq(token.allowance(ALICE, address(vault)), amount);
    }

    // ═════════════════════════════════════════════════════════════════════
    // HELPERS — Signing Functions
    // ═════════════════════════════════════════════════════════════════════
    // These helpers replicate the EIP-712 signing flow that a wallet does.
    // Developers: Study these to understand the full hashing chain.

    /// @dev Signs a Permit struct and returns (v, r, s)
    function _signPermit(
        address owner,
        uint256 signerPk,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        // 1. Build struct hash
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline)
        );

        // 2. Build EIP-712 digest
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash)
        );

        // 3. Sign
        (v, r, s) = vm.sign(signerPk, digest);
    }

    /// @dev Signs a Permit and submits it on-chain
    function _signAndSubmitPermit(
        address owner,
        uint256 signerPk,
        address spender,
        uint256 value,
        uint256 deadline
    ) internal {
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(owner, signerPk, spender, value, nonce, deadline);
        token.permit(owner, spender, value, deadline, v, r, s);
    }

    /// @dev Signs a WithdrawAuthorization struct (vault's custom EIP-712 type)
    function _signWithdraw(
        address owner,
        uint256 signerPk,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        // Note: This uses the VAULT's domain separator, not the token's!
        bytes32 structHash = keccak256(
            abi.encode(vault.WITHDRAW_TYPEHASH(), owner, to, amount, nonce, deadline)
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash)
        );

        (v, r, s) = vm.sign(signerPk, digest);
    }

    /// @dev Deposits tokens into vault for testing withdrawals
    function _depositToVault(address owner, uint256 ownerPk, uint256 amount) internal {
        uint256 nonce = token.nonces(owner);
        uint256 deadline = block.timestamp + 1 hours;

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            owner, ownerPk, address(vault), amount, nonce, deadline
        );

        vault.depositWithPermit(owner, amount, deadline, v, r, s);
    }
}
