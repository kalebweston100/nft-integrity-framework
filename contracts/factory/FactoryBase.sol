//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/ITokenFactory.sol";
import "../interfaces/IIntegrityToken.sol";
import "../interfaces/IHooks.sol";
import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";

/**
 * @title FactoryBase
 * @notice Abstract base for token factories that deploy framework token contracts.
 *         Contains shared state, verification logic, hooks initialization, registration,
 *         and per-deploy fee collection.
 *         Per-standard factories inherit this and implement their own deploy function.
 *
 * ARCHITECTURE:
 *   The factory deploys the token contract (the user-facing token) directly.
 *   Developers provide a hooks contract address — the token calls hooks via
 *   external call during the transfer/mint pipeline. The developer's hooks
 *   contract has its own storage and CANNOT access token state.
 *
 *   Deploying is permissionless — anyone can call deployToken* and become the
 *   issuer admin of their own token, subject only to the configurable deploy fee.
 *
 * CHAIN OF TRUST:
 *   factory.deployedByFactory(tokenAddr) -> true
 *   token.factory() -> this factory
 *   token.hooksContract() -> developer's hooks address (or address(0))
 *
 * SECURITY MODEL:
 *   - Token is deployed by THIS factory via `new`
 *   - Hooks address is immutable in the token — set at deployment
 *   - Factory calls hooks.initializeToken() to link hooks to the token (once only)
 *   - All core pipeline logic is locked in the concrete token contract
 *   - Developer's hooks contract can only ADD restrictions, not bypass checks
 *
 * DEPLOY FEE:
 *   Owner sets a per-deploy ETH fee via setDeployFee(). Each deployToken* call must
 *   include msg.value >= deployFee. Accumulated fees are withdrawn via withdrawFees().
 *   Default fee is 0 (free) until the owner sets one.
 */
abstract contract FactoryBase is ITokenFactory {
    // =========================================================================
    //                              EVENTS
    // =========================================================================

    event TokenDeployed(
        address indexed token,
        address indexed hooksContract,
        address indexed issuerAdmin,
        TokenStandard standard,
        uint256 deployedAt
    );

    event DeployFeeSet(uint256 newFee);
    event FeesWithdrawn(address indexed to, uint256 amount);

    // =========================================================================
    //                          STATE VARIABLES
    // =========================================================================

    /// @notice The factory owner (platform operator).
    address public owner;

    /// @notice Per-deploy ETH fee. Zero by default (free). Set by owner via setDeployFee().
    uint256 public deployFee;

    /// @notice Accumulated deploy fees available for withdrawal.
    uint256 public feeBalance;

    /// @notice Tracks all tokens deployed through this factory.
    mapping(address => bool) private _deployedByFactory;

    /// @notice Maps token -> its hooks contract (address(0) if none).
    mapping(address => address) public hooksOf;

    /// @notice Array of all deployed token addresses (for enumeration).
    address[] public deployedTokens;

    // =========================================================================
    //                             MODIFIERS
    // =========================================================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // =========================================================================
    //                            CONSTRUCTOR
    // =========================================================================

    constructor() {
        owner = msg.sender;
    }

    // =========================================================================
    //                          DEPLOY FEE
    // =========================================================================

    /// @notice Sets the ETH fee required per token deployment. Zero disables the fee.
    function setDeployFee(uint256 fee) external onlyOwner {
        deployFee = fee;
        emit DeployFeeSet(fee);
    }

    /// @notice Withdraws accumulated deploy fees to `to`.
    function withdrawFees(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = feeBalance;
        if (amount == 0) revert NothingToWithdraw();
        feeBalance = 0;
        (bool success,) = payable(to).call{value: amount}("");
        if (!success) revert WithdrawalFailed();
        emit FeesWithdrawn(to, amount);
    }

    /// @notice Checks that msg.value covers the deploy fee and accumulates it.
    /// @dev Called at the top of each payable deployToken* function.
    function _checkAndCollectFee() internal {
        if (msg.value < deployFee) revert InsufficientDeployFee();
        feeBalance += msg.value;
    }

    // =========================================================================
    //                     INTERNAL VERIFY & REGISTER
    // =========================================================================

    /// @notice Shared verification and registration logic for all standards.
    function _verifyAndRegister(address token, address hooksAddr, address issuerAdminAddr) internal {
        IIntegrityToken deployed = IIntegrityToken(token);
        if (!deployed.isIntegrityToken()) revert NotIntegrityToken();

        TokenStandard standard = deployed.tokenStandard();

        _deployedByFactory[token] = true;
        hooksOf[token] = hooksAddr;
        deployedTokens.push(token);

        emit TokenDeployed(token, hooksAddr, issuerAdminAddr, standard, block.timestamp);
    }

    // =========================================================================
    //                     INTERNAL HOOKS INITIALIZATION
    // =========================================================================

    /// @notice Initialize the hooks contract by linking it to the deployed token.
    /// @dev Called by child factories after deploying the token. Only works if
    ///      hooksAddr is not address(0). The hooks contract must have been deployed
    ///      with this factory's address so that onlyFactory passes.
    function _initializeHooks(address hooksAddr, address token) internal {
        if (hooksAddr != address(0)) {
            IInitializableHooks(hooksAddr).initializeToken(token);
        }
    }

    // =========================================================================
    //                     CHAIN-OF-TRUST VERIFICATION
    // =========================================================================

    /// @notice Verify the full chain of trust for a deployed token (any standard).
    /// @param token The token address to verify.
    /// @return valid True if the full chain of trust is intact.
    function verifyChainOfTrust(address token) external view returns (bool valid) {
        if (!_deployedByFactory[token]) return false;

        IIntegrityToken tokenContract = IIntegrityToken(token);

        if (tokenContract.factory() != address(this)) return false;

        address hooksAddr = hooksOf[token];
        if (hooksAddr != address(0)) {
            if (tokenContract.hooksContract() != hooksAddr) return false;
            IInitializableHooks hooks = IInitializableHooks(hooksAddr);
            if (hooks.factory() != address(this)) return false;
            if (hooks.tokenContract() != token) return false;
        }

        return true;
    }

    // =========================================================================
    //                     BYTECODE / IMPLEMENTATION VERIFICATION
    // =========================================================================
    //
    // This framework is distributed as source that developers compile and deploy
    // themselves — there is no shared, hosted, or maintained factory instance and
    // no on-chain registry of "known good" deployments. Trust is established by
    // comparing a deployed factory's own runtime bytecode hash (EXTCODEHASH)
    // against the canonical hash for the framework version you're integrating
    // with, published alongside that version's source (see README: "Verifying a
    // deployment"). FactoryBase and its concrete subclasses (FactoryERC20/721/1155)
    // hold no `immutable` state, so every canonical deployment — regardless of
    // deployer or constructor-time `owner` — produces byte-identical runtime
    // bytecode, which is what makes this comparison meaningful.

    /// @notice Checks an arbitrary address's runtime bytecode hash against an
    ///         expected value, e.g. the canonical hash for a given release of this
    ///         framework. Safe to use against an UNTRUSTED `target`: EXTCODEHASH is
    ///         computed by the EVM from the target's actual deployed bytecode, so a
    ///         malicious contract cannot misreport it — this function never calls
    ///         into `target`, it only reads its code hash.
    /// @dev Prefer this over calling a "isCanonical()"-style function ON a factory
    ///      you don't already trust: a maliciously modified factory could simply
    ///      hardcode such a function to return true. Only EXTCODEHASH, read
    ///      externally as done here, cannot be spoofed by the target's own logic.
    function isCanonicalCodeHash(address target, bytes32 expectedCodeHash) public view returns (bool) {
        return target.codehash == expectedCodeHash;
    }

    /// @notice Convenience getter for this factory's own runtime bytecode hash.
    /// @dev Pure self-report — see `isCanonicalCodeHash` NatSpec for why a verifier
    ///      checking an UNTRUSTED factory should compute `target.codehash` directly
    ///      (or call `isCanonicalCodeHash` on a factory instance already trusted)
    ///      rather than rely on this function's return value from the factory being
    ///      verified.
    function runtimeCodeHash() external view returns (bytes32) {
        return address(this).codehash;
    }

    // =========================================================================
    //                          VIEW FUNCTIONS
    // =========================================================================

    function deployedByFactory(address token) external view returns (bool) {
        return _deployedByFactory[token];
    }

    function deployedTokenCount() external view returns (uint256) {
        return deployedTokens.length;
    }

    // =========================================================================
    //                        OWNERSHIP TRANSFER
    // =========================================================================

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }
}
