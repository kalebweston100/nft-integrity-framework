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
error TransferRejected();

// ─── ERC-721 token lifecycle ─────────────────────────────────────────────────
error TokenNotOwned();
error TokenAlreadyMinted();
error NonexistentToken();

// ─── Receiver checks ─────────────────────────────────────────────────────────
error NotERC721Receiver();
error NotERC1155Receiver();

// ─── Royalty ─────────────────────────────────────────────────────────────────
error RoyaltyTooHigh();

// ─── Admin / pause ───────────────────────────────────────────────────────────
error NotIssuerAdmin();
error TokenPaused();
error AlreadyPaused();
error NotPaused();
