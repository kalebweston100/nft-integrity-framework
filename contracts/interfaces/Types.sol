//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Types
 * @notice Shared data types for the canonical token set.
 */

/**
 * @notice Identifies which token standard a canonical token implements.
 * @dev Returned by tokenStandard() on every member of the set, and carried in
 *      ActionContext so one PolicyEngine can serve all three. Lets an
 *      integrator pick the right interface without trial-and-error detection,
 *      and tells a policy reader how to interpret `id` and `amount` in a rule.
 *
 * ERC20    Fungible (EIP-20). One balance per address; `id` is unused.
 * ERC721   Non-fungible (EIP-721). `id` is the token id, `amount` is always 1.
 * ERC1155  Multi-token (EIP-1155). Per-id balances; both fields are used, and
 *          supply and holder counts are per-id.
 */
enum TokenStandard {
    ERC20,
    ERC721,
    ERC1155
}
