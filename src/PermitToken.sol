// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @title PermitToken — ERC20 Token with ERC-2612 Permit Gasless Approvals
/// @author Agustin Acosta
/// @notice An ERC20 token implementing the ERC-2612 Permit standard
/// using EIP-712 typed structured data signing for gasless approvals.
///
/// ══════════════════════════════════════════════════════════════════════════════
/// WHAT IS ERC-2612 PERMIT?
/// ══════════════════════════════════════════════════════════════════════════════
///
/// Normally, to let a contract spend your tokens, you need TWO transactions:
///   1. approve(spender, amount)  — costs gas
///   2. transferFrom(...)         — costs gas
///
/// With Permit, the owner signs an off-chain message (no gas!) and anyone
/// can submit that signature on-chain to set the allowance:
///   1. Owner signs a Permit message off-chain (FREE — no gas)
///   2. Anyone calls permit(owner, spender, value, deadline, v, r, s) — ONE tx
///   3. The spender can now call transferFrom(...)
///
/// This enables "gasless approvals" — the token owner doesn't even need ETH!
///
/// ══════════════════════════════════════════════════════════════════════════════
/// OPENZEPPELIN'S IMPLEMENTATION
/// ══════════════════════════════════════════════════════════════════════════════
///
/// OpenZeppelin provides a battle-tested ERC20Permit extension that:
///   - Inherits from ERC20, IERC20Permit, EIP712, and Nonces
///   - Implements permit() with EIP-712 typed data signing
///   - Manages nonces automatically via _useNonce()
///   - Computes domain separator with chain fork protection
///   - Uses ECDSA.recover for safe signature verification
///
/// THE PERMIT STRUCT (EIP-712 Typed Data) that gets signed:
///
///   Permit(address owner, address spender, uint256 value, uint256 nonce, uint256 deadline)
///
/// - owner:    who is granting the allowance
/// - spender:  who is allowed to spend
/// - value:    how many tokens
/// - nonce:    prevents replay attacks (increments after each use)
/// - deadline: signature expires after this timestamp
///
contract PermitToken is ERC20, ERC20Permit {

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    /// @param _name Token name (also used as EIP-712 domain name)
    /// @param _symbol Token symbol
    /// @param _initialSupply Initial supply minted to deployer
    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _initialSupply
    )
        ERC20(_name, _symbol)
        ERC20Permit(_name)
    {
        _mint(msg.sender, _initialSupply);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INHERITED FUNCTIONALITY (from OpenZeppelin)
    // ═══════════════════════════════════════════════════════════════════════
    //
    // From ERC20:
    //   - transfer(to, value)
    //   - approve(spender, value)
    //   - transferFrom(from, to, value)
    //   - balanceOf(account)
    //   - allowance(owner, spender)
    //   - totalSupply()
    //   - name(), symbol(), decimals()
    //
    // From ERC20Permit (ERC-2612):
    //   - permit(owner, spender, value, deadline, v, r, s)
    //   - nonces(owner) — per-address nonce for replay protection
    //   - DOMAIN_SEPARATOR() — EIP-712 domain separator
    //
    // From EIP712:
    //   - eip712Domain() — ERC-5267 domain info getter
    //
    // Errors (from ERC20Permit):
    //   - ERC2612ExpiredSignature(uint256 deadline)
    //   - ERC2612InvalidSigner(address signer, address owner)
    //
}
