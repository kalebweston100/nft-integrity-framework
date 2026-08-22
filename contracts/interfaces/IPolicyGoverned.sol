//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./Types.sol";

/**
 * @title IPolicyGoverned
 * @notice The discovery interface: how an integrator finds a token's policy
 *         without knowing anything else about the token.
 *
 * @dev Advertised via ERC-165, so a wallet, marketplace or indexer can ask any
 *      address `supportsInterface(type(IPolicyGoverned).interfaceId)` and, if
 *      the answer is yes, read the complete set of conditions under which that
 *      token can block a transfer.
 *
 *      THIS INTERFACE IS NOT THE GUARANTEE. Anything can implement it and
 *      return an address. What makes the answer trustworthy is that the token's
 *      own runtime codehash matches a member of the canonical set — see
 *      contracts/verification/PolicyVerification.sol. The interface only makes
 *      the policy FINDABLE; the codehash is what makes the rule list EXHAUSTIVE.
 *
 *      The split matters for adoption: discovery should be cheap and universal,
 *      verification deliberate. An integrator that only implements discovery
 *      still gets a better error message than a bare revert; one that also
 *      checks the hash gets the actual claim.
 */
interface IPolicyGoverned {
    /// @notice The PolicyEngine holding this token's complete transfer policy.
    /// @dev Never address(0) for a canonical token: the engine is deployed by
    ///      the token's own constructor and there is no setter.
    function policy() external view returns (address);

    /// @notice Which token standard this contract implements, so a reader knows
    ///         how to interpret `id` and `amount` in the policy's rules.
    function tokenStandard() external view returns (TokenStandard);
}
