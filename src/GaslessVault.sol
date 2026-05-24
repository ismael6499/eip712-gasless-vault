// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {PermitToken} from "./PermitToken.sol";

/// @title GaslessVault — Secure EIP-712 Custom Signed Vault Authorizations
/// @author Agustin Acosta
/// @notice A gasless vault protocol demonstrating custom EIP-712 typed data signing,
/// enabling trustless relayer-mediated deposits and custom-authorized withdrawals.
/// @dev Combines OpenZeppelin's EIP712, Nonces, ReentrancyGuard, and SafeERC20 utilities.
///
/// ══════════════════════════════════════════════════════════════════════════════
/// WHY THIS CONTRACT?
/// ══════════════════════════════════════════════════════════════════════════════
///
/// The PermitToken shows the standard ERC-2612 use of EIP-712. But EIP-712 is
/// a GENERAL-PURPOSE standard — you can define ANY typed data struct!
///
/// This vault shows how to create a custom EIP-712 struct:
///
///   WithdrawAuthorization — "I authorize someone to withdraw my vault balance"
///   Enables gasless withdrawals via a signed message.
///
/// It also demonstrates gasless deposits by combining the token's permit()
/// with the vault's deposit, all in a single transaction submitted by a relayer.
///
/// ══════════════════════════════════════════════════════════════════════════════
/// OPENZEPPELIN BUILDING BLOCKS
/// ══════════════════════════════════════════════════════════════════════════════
///
/// This contract uses three OZ utilities:
///
///   1. EIP712 — Provides _hashTypedDataV4(structHash) and _domainSeparatorV4()
///      Handles domain separator caching, chain fork protection, and the
///      "\x19\x01" prefix automatically.
///
///   2. ECDSA — Provides ECDSA.recover(hash, v, r, s) for safe signature recovery.
///      Handles signature malleability checks (s in lower half) internally.
///
///   3. Nonces — Provides _useNonce(owner) for atomic nonce management.
///      Same pattern used by ERC20Permit for replay protection.
///
/// ══════════════════════════════════════════════════════════════════════════════
/// CUSTOM TYPE HASHES
/// ══════════════════════════════════════════════════════════════════════════════
///
/// Each EIP-712 struct needs its own TYPE HASH. The type hash is the keccak256
/// of the "type string" — a canonical representation of the struct's fields.
///
/// Rules for type strings:
///   - Format: "StructName(type1 name1,type2 name2,...)"
///   - NO spaces after commas
///   - Fields in declaration order
///   - Use Solidity types (address, uint256, bytes32, etc.)
///
contract GaslessVault is EIP712, Nonces, ReentrancyGuard {
    using SafeERC20 for PermitToken;
    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice The ERC20 token this vault accepts
    PermitToken public immutable token;

    /// @notice Vault balances per depositor
    mapping(address depositor => uint256) public vaultBalanceOf;

    // ═══════════════════════════════════════════════════════════════════════
    // TYPE HASHES — Defining Custom EIP-712 Structs
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Type hash for WithdrawAuthorization struct.
    /// @dev Type string: "WithdrawAuthorization(address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)"
    ///
    /// This tells EIP-712: "When I sign a WithdrawAuthorization, it has these fields in this order."
    /// Wallets that support EIP-712 will display this information to the user before signing.
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "WithdrawAuthorization(address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error DeadlineExpired();
    error InvalidWithdrawSignature();
    error InsufficientVaultBalance();
    error ZeroAmount();
    error InvalidAddress();

    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    event Deposited(address indexed depositor, uint256 amount);
    event Withdrawn(address indexed owner, address indexed to, uint256 amount);

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    /// @param _token The PermitToken this vault accepts
    constructor(PermitToken _token) EIP712("GaslessVault", "1") {
        if (address(_token) == address(0)) revert InvalidAddress();
        token = _token;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DIRECT DEPOSIT (requires prior approve)
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Deposit tokens into the vault (requires prior ERC20 approval)
    function deposit(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();

        vaultBalanceOf[msg.sender] += amount;
        token.safeTransferFrom(msg.sender, address(this), amount);

        emit Deposited(msg.sender, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GASLESS DEPOSIT (Permit + Deposit in one transaction)
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Deposit tokens using an ERC-2612 Permit signature — no prior approval needed!
    /// @dev This combines TWO operations in one transaction:
    ///   1. Call token.permit() to set allowance via signature
    ///   2. Call token.transferFrom() to deposit
    ///
    /// A relayer can call this on behalf of the token owner.
    /// The owner only needs to sign the permit off-chain (no gas).
    ///
    /// @param owner The token owner who signed the permit
    /// @param amount How many tokens to deposit
    /// @param deadline Permit signature expiry
    /// @param v ECDSA recovery byte for the permit signature
    /// @param r ECDSA signature component for the permit signature
    /// @param s ECDSA signature component for the permit signature
    function depositWithPermit(
        address owner,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (amount == 0) revert ZeroAmount();

        // Step 1: Use the permit signature to approve this vault
        token.permit(owner, address(this), amount, deadline, v, r, s);

        // Step 2: Transfer tokens from owner to vault
        vaultBalanceOf[owner] += amount;
        token.safeTransferFrom(owner, address(this), amount);

        emit Deposited(owner, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DIRECT WITHDRAW
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Withdraw your tokens from the vault
    function withdraw(address to, uint256 amount) external nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert ZeroAmount();
        if (vaultBalanceOf[msg.sender] < amount) revert InsufficientVaultBalance();

        vaultBalanceOf[msg.sender] -= amount;
        token.safeTransfer(to, amount);

        emit Withdrawn(msg.sender, to, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GASLESS WITHDRAW (Custom EIP-712 Signed Authorization)
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Withdraw tokens using an EIP-712 signed authorization.
    /// @dev This demonstrates a CUSTOM EIP-712 struct (not just Permit!).
    ///
    /// THE SIGNING FLOW (same pattern as Permit, different struct):
    ///
    /// 1. STRUCT HASH:
    ///    structHash = keccak256(abi.encode(
    ///        WITHDRAW_TYPEHASH,  // "I'm signing a WithdrawAuthorization"
    ///        owner,              // who owns the vault balance
    ///        to,                 // where to send the tokens
    ///        amount,             // how many tokens
    ///        nonce,              // replay protection (managed by OZ Nonces)
    ///        deadline            // expiry
    ///    ))
    ///
    /// 2. DIGEST (handled by OZ's _hashTypedDataV4):
    ///    digest = keccak256("\x19\x01" || DOMAIN_SEPARATOR || structHash)
    ///
    ///    IMPORTANT: This vault has its OWN domain separator (name="GaslessVault"),
    ///    different from the token's domain separator (name="PermitToken").
    ///    This is why signatures cannot be replayed across contracts!
    ///
    /// 3. VERIFY (handled by OZ's ECDSA.recover):
    ///    signer = ecrecover(digest, v, r, s)
    ///    require(signer == owner)
    ///
    /// @param owner The vault depositor who signed the authorization
    /// @param to The recipient of the withdrawn tokens
    /// @param amount How many tokens to withdraw
    /// @param deadline Authorization expiry timestamp
    /// @param v ECDSA recovery byte
    /// @param r ECDSA signature component
    /// @param s ECDSA signature component
    function withdrawBySig(
        address owner,
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        // Check: deadline
        if (to == address(0)) revert InvalidAddress();
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (amount == 0) revert ZeroAmount();
        if (vaultBalanceOf[owner] < amount) revert InsufficientVaultBalance();

        // Step 1: Build the struct hash for WithdrawAuthorization
        // _useNonce atomically reads AND increments the nonce (from OZ Nonces)
        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAW_TYPEHASH,
                owner,
                to,
                amount,
                _useNonce(owner),
                deadline
            )
        );

        // Step 2: Compute EIP-712 digest (OZ handles "\x19\x01" prefix + domain separator)
        bytes32 digest = _hashTypedDataV4(structHash);

        // Step 3: Recover signer and verify (OZ ECDSA handles malleability checks)
        address signer = ECDSA.recover(digest, v, r, s);
        if (signer != owner) revert InvalidWithdrawSignature();

        // Effects: update balance (nonce already incremented by _useNonce)
        vaultBalanceOf[owner] -= amount;

        // Interaction: transfer tokens
        token.safeTransfer(to, amount);

        emit Withdrawn(owner, to, amount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Returns the domain separator for this contract (EIP-712)
    /// @dev Each contract has its OWN domain separator (different name + address),
    /// which prevents signature replay across contracts.
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
