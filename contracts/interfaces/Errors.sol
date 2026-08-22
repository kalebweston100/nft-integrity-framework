// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

// ─── General ─────────────────────────────────────────────────────────────────
error ZeroAddress();
error LengthMismatch();

// ─── Balances / allowances ───────────────────────────────────────────────────
error InsufficientBalance();
error InsufficientAllowance();

// ─── Transfer / approval ─────────────────────────────────────────────────────
error NotOwnerOrApproved();
error NotOwnerOrOperator();
error SelfApproval();

// ─── ERC-721 token lifecycle ─────────────────────────────────────────────────
error TokenNotOwned();
error TokenAlreadyMinted();
error NonexistentToken();

// ─── Receiver checks ─────────────────────────────────────────────────────────
error NotERC721Receiver();
error NotERC1155Receiver();

// ─── Royalty ─────────────────────────────────────────────────────────────────
error RoyaltyTooHigh();

// ─── Admin ───────────────────────────────────────────────────────────────────
// NOTE: there is deliberately no pause error. The canonical tokens have no
// pause, and never will — a discretionary halt is a blocking condition outside
// the rule array, which is exactly what this design exists to eliminate. See
// contracts/token/PolicyERC20.sol.
error NotIssuerAdmin();
