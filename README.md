# EIP-712 Gasless Transaction Vault Protocol

![Solidity](https://img.shields.io/badge/Solidity-0.8.26-363636?style=flat-square&logo=solidity)
![Security](https://img.shields.io/badge/Security-SafeERC20_&_ReentrancyGuard-blueviolet?style=flat-square)
![Coverage](https://img.shields.io/badge/Coverage-100.00%25-brightgreen?style=flat-square)

A secure, gas-optimized Vault protocol showcasing general-purpose EIP-712 typed structured data signing. The architecture enables trustless relayer-mediated deposits (via ERC-2612 `permit`) and custom-authorized withdrawals (via custom `WithdrawAuthorization` typed signatures), eliminating the gas fee requirements for the end-user.

---

## 🏗 Architecture & Security Features

### 1. Replay & Cross-Contract Replay Protection
- **Context:** Signed authorizations are vulnerable to replay attacks on other contracts, forks, or different EVM-compatible chains if the signature is simply a hash of the raw arguments.
- **Implementation:** Both `PermitToken` and `GaslessVault` calculate unique EIP-712 domain separators.
  - **`DOMAIN_SEPARATOR` Components:** Cryptographically binds the signature to the contract's name, version (`"1"`), `block.chainid` (fork protection), and the deployment address (`address(this)`).
  - A signature authorized for `PermitToken` will automatically revert if presented to the `GaslessVault` or an evil clone because the domain separators do not match.

### 2. Custom Typed Data Authorizations (`WithdrawAuthorization`)
- **Context:** Standard EIP-712 usage in ERC-20 tokens is limited to the ERC-2612 `permit` (allowance setting). However, EIP-712 is a general-purpose standard capable of signing any custom struct.
- **Implementation:** The `GaslessVault` implements a custom struct hash for withdrawal authorization:
  ```solidity
  bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
      "WithdrawAuthorization(address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)"
  );
  ```
  - **Replay Protection via Nonces:** Incorporates an atomic `_useNonce(owner)` query (from OpenZeppelin's `Nonces`) which automatically reads and increments the owner's nonce per transaction.
  - **Deadline Enforcement:** Ensures that signed messages are time-bound, immediately reverting if the transaction is executed past the specified `deadline`.

### 3. Trustless Relayer-Mediated Deposits (ERC-2612)
- **Context:** Standard ERC-20 deposits require two separate on-chain transactions: `approve()` and `transferFrom()`, both costing gas to the depositor.
- **Implementation:** The vault provides `depositWithPermit()`, which takes the signature components (`v, r, s`) to set the allowance on-chain via the token's `permit()` function and completes the vault deposit in a single atomic transaction. The token owner only signs an off-chain message, leaving the gas payment to the relayer.

### 4. Defense in Depth Security Hardening
- **SafeERC20 Integrations:** To prevent compatibility issues with non-standard ERC-20 tokens (e.g., those returning `false` instead of reverting, or returning no boolean at all), the vault utilizes OpenZeppelin's `SafeERC20` module for all token transfers (`safeTransfer`, `safeTransferFrom`).
- **Reentrancy Protection:** All withdrawal entry points (`withdraw`, `withdrawBySig`) are protected by inheriting OpenZeppelin's standard `ReentrancyGuard` module and applying the `nonReentrant` modifier, enforcing robust Checks-Effects-Interactions (CEI) semantics.
- **Zero Address Validation:** Prevents loss of funds by explicitly reverting with `InvalidAddress()` if a zero address is supplied in the constructor, direct withdrawals, or signature-authorized withdrawals.

---

## 🧪 Testing & Quality Assurance

The test suite is built in **Foundry**, asserting cryptographically secure signature verification, custom authorization flows, boundaries, and fuzzing constraints with **100.00% line coverage**.

It features:
- **Crypto-Random Fuzzing:** Binds fuzzed inputs using `bound()` to verify that valid permit signatures operate correctly under all mathematically valid ranges.
- **Exclusion Invariants:** Fuzzes random private keys to prove that only the legitimate owner can sign valid permits and withdrawals.
- **Edge-Case Validation:** Asserts reverts for expired deadlines, zero amounts, zero addresses, and attempts to replay signatures.

To execute the test suite:
```bash
forge test
```

To run code coverage analysis:
```bash
forge coverage
```

**Coverage Report:**
```text
╭----------------------+-----------------+----------------+----------------+---------------╮
| File                 | % Lines         | % Statements   | % Branches     | % Funcs       |
+==========================================================================================+
| src/GaslessVault.sol | 100.00% (35/35) | 97.73% (43/44) | 90.91% (10/11) | 100.00% (6/6) |
|----------------------+-----------------+----------------+----------------+---------------|
| src/PermitToken.sol  | 100.00% (2/2)   | 100.00% (1/1)  | 100.00% (0/0)  | 100.00% (1/1) |
|----------------------+-----------------+----------------+----------------+---------------|
| Total                | 100.00% (37/37) | 97.78% (44/45) | 90.91% (10/11) | 100.00% (7/7) |
╰----------------------+-----------------+----------------+----------------+---------------╯
```
