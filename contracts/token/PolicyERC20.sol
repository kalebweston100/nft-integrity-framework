//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "../interfaces/IPolicyGoverned.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";
import "./PolicyTokenBase.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title PolicyERC20
 * @notice A canonical ERC-20 whose complete transfer policy is enumerable data
 *         held in a canonical PolicyEngine that this contract deploys itself.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE CLAIM
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *     Beyond the ERC-20 standard's own requirements — sufficient balance,
 *     sufficient allowance, non-zero recipient — the ONLY conditions under
 *     which this token can block a transfer are the rules enumerated by
 *     policy().rules(). No other condition exists, and none can be added
 *     without swapDelay seconds of public, on-chain notice.
 *
 * That claim needs three things, all of which hold here and none of which hold
 * for a token wired to a bespoke policy contract:
 *
 *   1. THE ENTRY POINT IS CANONICAL. Whatever address a user transacts with
 *      decides whether the call reverts. keccak256(type(PolicyERC20).runtimeCode)
 *      identifies this exact code, so a verifier can establish that the
 *      transfer path below is the one that ran. This is why the contract holds
 *      zero immutables and is not virtual and not upgradeable.
 *
 *   2. THE POLICY IS CANONICAL. The engine is deployed by this contract's
 *      constructor with CREATE2, from creation code embedded in this bytecode.
 *      There is no setter and no path by which it could be anything else — the
 *      guarantee costs zero gas because it is structural rather than checked.
 *
 *   3. THE TRANSFER PATH HAS EXACTLY ONE DISCRETIONARY GATE. See _transfer().
 *      Every revert in it is either an ERC-20 correctness requirement or the
 *      policy verdict. Adding any other `revert` to that function falsifies the
 *      headline claim — treat it as a breaking change to the guarantee, not a
 *      feature.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE UNCONDITIONAL CASE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * When the rule array is EMPTY the claim reads: nothing this token can do will
 * ever block your transfer. That is not a degenerate configuration — it is the
 * strongest statement the design makes, and no ordinary token can make it.
 *
 * A negative claim over arbitrary code ("no hidden condition exists") cannot be
 * established by observing behaviour, at any cost, ever. It becomes checkable
 * only because the code is fixed and published: verification moves the question
 * from runtime to compile time. An empty policy behind a canonical hash is
 * therefore a machine-checkable proof of ABSENCE — see
 * PolicyVerification.isUnconditional.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THERE IS NO pause()
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Deliberate, and the sharpest consequence of the design. A pause is a
 * discretionary revert in the transfer path held by the issuer — exactly the
 * unenumerable, un-noticed blocking power this contract exists to eliminate. A
 * token with both `pause()` and an enumerable policy cannot make claim 3.
 *
 * The capability is not lost, only made honest: halting transfers is a rule
 * (LockupUntil with a future timestamp), and adding it therefore takes the
 * timelock like any other policy change. An issuer cannot silently freeze a
 * market and cannot do it without notice. That is the point, not a limitation.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * EVERY ENTRY POINT IS GOVERNED
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * There is no carve-out. `transfer`, `approve`, `mint` and `burn` each consult
 * the policy for their own Action, so the claim above is total over the ABI
 * rather than scoped to transfers. A policy may leave any action ungated, and
 * an ungated action costs one warm SLOAD inside the engine.
 *
 * Two exemptions are structural rather than policy, because a rule that could
 * impose them would be a trap:
 *
 *   - REDUCING an allowance is never gated. De-risking must always succeed; a
 *     policy able to prevent you lowering an approval could pin you to it.
 *   - `burn` destroys the caller's own balance and nothing else. There is no
 *     admin path to another holder's tokens: an admin able to burn from an
 *     arbitrary address holds a confiscation lever, strictly stronger than the
 *     freeze this contract refuses to implement. Blocking a transfer stops you
 *     moving a token; burning takes it outright.
 *
 * `mint` stays issuer-admin gated on top of its policy — the admin check is an
 * authorization requirement, not a discretionary blocking condition, and the
 * issuer controls supply regardless.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ZERO IMMUTABLES — LOAD-BEARING
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Every field, here and in PolicyTokenBase, is plain storage written once in a
 * constructor with no setter. Adding one `immutable` stops the verifier
 * compiling; the constraint enforces itself. See
 * contracts/verification/CanonicalCode.sol.
 */
contract PolicyERC20 is PolicyTokenBase {
    // =========================================================================
    //                                  EVENTS
    // =========================================================================

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // =========================================================================
    //                        STATE — ALL PLAIN STORAGE
    // =========================================================================

    string private _name;
    string private _symbol;

    /// @dev Plain storage, not a constant. Real assets are not all 18 decimals
    ///      (USDC is 6, WBTC is 8) and a canonical set that cannot express that
    ///      is not usable. `immutable` would break type(C).runtimeCode, so the
    ///      value is written once in the constructor like everything else.
    uint8 private _decimals;

    uint256 private _totalSupply;

    /// @notice Count of addresses holding a non-zero balance. Maintained here
    ///         because the HolderCap rule needs it and no ERC-20 exposes it;
    ///         the policy is never permitted to call back to fetch it.
    uint256 private _holderCount;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // =========================================================================
    //                               CONSTRUCTOR
    // =========================================================================

    /// @param admin         Issuer admin: may mint and change policy rules.
    /// @param tokenName     ERC-20 name.
    /// @param tokenSymbol   ERC-20 symbol.
    /// @param tokenDecimals ERC-20 decimals.
    /// @param swapDelay     Seconds of notice before a rule change commits.
    /// @param initialRules  The policy at launch. Empty means unconditional —
    ///                      see the contract NatSpec.
    constructor(
        address admin,
        string memory tokenName,
        string memory tokenSymbol,
        uint8 tokenDecimals,
        uint256 swapDelay,
        Rule[] memory initialRules
    ) PolicyTokenBase(admin, swapDelay, initialRules) {
        _name = tokenName;
        _symbol = tokenSymbol;
        _decimals = tokenDecimals;
    }

    // =========================================================================
    //                     ERC-20 VIEWS (non-virtual, locked)
    // =========================================================================

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    /// @inheritdoc IPolicyGoverned
    function tokenStandard() external pure returns (TokenStandard) {
        return TokenStandard.ERC20;
    }

    /// @notice Number of addresses holding a non-zero balance.
    function holderCount() external view returns (uint256) {
        return _holderCount;
    }

    /// @notice Whether the policy would currently allow this transfer, and why
    ///         not if it would not. Free to call; changes nothing.
    /// @dev The integrator's alternative to a failed transaction. A marketplace
    ///      or wallet can call this before submitting and render the reason.
    function canTransfer(address from, address to, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (to == address(0)) return (false, "zero recipient");
        if (_balances[from] < amount) return (false, "insufficient balance");
        return _policy.evaluate(_ctx(Action.Transfer, from, from, to, amount));
    }

    /// @notice The policy verdict for any action, not only transfers.
    /// @dev Standard-conformance requirements are NOT checked here — this
    ///      answers "would the policy allow it", which is the half an
    ///      integrator cannot work out for itself. Balances are read from
    ///      storage, so a caller supplies only the action-specific arguments.
    function canPerform(Action action, address actor, address from, address to, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason)
    {
        return _policy.evaluate(_ctx(action, actor, from, to, amount));
    }

    /// @notice ERC-165. Advertises IPolicyGoverned so an integrator can discover
    ///         the policy without knowing anything else about this token.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC20).interfaceId || interfaceId == type(IPolicyGoverned).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // =========================================================================
    //                  ERC-20 ENTRY POINTS (non-virtual, locked)
    // =========================================================================

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        if (allowed < amount) revert InsufficientAllowance();
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    /// @dev Only an INCREASE is gated. Reducing or revoking an allowance is
    ///      always permitted: a policy able to stop you lowering an approval
    ///      could pin you to it, which is a trap rather than a restriction.
    function approve(address spender, uint256 amount) external returns (bool) {
        if (amount > _allowances[msg.sender][spender]) {
            _gate(_ctx(Action.Approve, msg.sender, msg.sender, spender, amount));
        }
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // =========================================================================
    //                          THE TRANSFER PATH
    // =========================================================================

    /**
     * @dev THE LOAD-BEARING FUNCTION. Every `revert` reachable from here is
     *      either an ERC-20 correctness requirement or the policy verdict, and
     *      that exhaustiveness IS the product. Do not add a discretionary
     *      revert to this function — not a pause, not a role check, not an
     *      emergency switch. Any such addition silently falsifies the claim in
     *      this contract's NatSpec while leaving every test green.
     *
     *      Zero-value transfers succeed, as ERC-20 requires, and are still
     *      policy-gated: a blocklisted sender is refused even at zero value,
     *      which is the standard-conforming reading.
     */
    function _transfer(address from, address to, uint256 amount) private {
        // [ERC-20 correctness] Not discretionary — required by the standard.
        if (to == address(0)) revert ZeroAddress();
        if (_balances[from] < amount) revert InsufficientBalance();

        // [THE ONLY DISCRETIONARY GATE] `evaluate` is `view`, so this is a
        // STATICCALL: the engine cannot write to any storage, cannot emit, and
        // cannot reenter this contract in any state-changing way. The read-only
        // flag covers the entire subcall frame to arbitrary depth, including
        // any registry or external gate a rule consults.
        _gate(_ctx(Action.Transfer, msg.sender, from, to, amount));

        // [LOCKED] Balance mutation. Nothing above this line has written state,
        // so the balances the policy saw are the pre-transfer values its
        // ActionContext documentation promises.
        _moveBalance(from, to, amount);

        emit Transfer(from, to, amount);

        // [POST-TRANSFER] Lets stateful rules (MinHoldTime) record what settled.
        // Gated to this token as `notifier` on the engine. The engine is
        // canonical, so this is not an untrusted call and needs no try/catch:
        // its only write is lastReceived, and a revert here can only mean a bug
        // in code the verifier has already checked.
        _policy.recordTransfer(_ctx(Action.Transfer, msg.sender, from, to, amount));
    }

    /// @dev Holder accounting is maintained on the 0 <-> non-zero transitions
    ///      only, so an ordinary transfer between two existing holders pays
    ///      nothing for it.
    ///
    ///      The self-transfer guard is load-bearing, not an optimisation.
    ///      Without it both balances are cached from the same slot, the credit
    ///      overwrites the debit, and `transfer(self, n)` inflates the sender's
    ///      balance by `n` out of nothing. A self-transfer moves no value and
    ///      creates no holder, so returning early is also the correct
    ///      accounting; the caller still emits Transfer, as ERC-20 requires.
    function _moveBalance(address from, address to, uint256 amount) private {
        if (from == to) return;

        uint256 fromBalance = _balances[from];
        uint256 toBalance = _balances[to];

        unchecked {
            _balances[from] = fromBalance - amount;
            _balances[to] = toBalance + amount;
        }

        if (amount > 0) {
            if (toBalance == 0) ++_holderCount;
            if (fromBalance == amount) --_holderCount;
        }
    }

    /// @dev The context the policy evaluates. The token PUSHES this; the policy
    ///      never calls back to fetch it, which is what lets balance-dependent
    ///      rules exist without any reverse call path.
    function _ctx(Action action, address actor, address from, address to, uint256 amount)
        private
        view
        returns (ActionContext memory)
    {
        return ActionContext({
            action: action,
            standard: TokenStandard.ERC20,
            actor: actor,
            from: from,
            to: to,
            id: 0,
            amount: amount,
            fromBalance: _balances[from],
            toBalance: _balances[to],
            totalSupply: _totalSupply,
            holderCount: _holderCount
        });
    }

    // =========================================================================
    //                                 SUPPLY
    // =========================================================================

    /// @notice Mint new supply. Unconditionally issuer-admin gated; see the
    ///         contract NatSpec for why this is outside the policy.
    function mint(address to, uint256 amount) external onlyIssuerAdmin {
        if (to == address(0)) revert ZeroAddress();

        _gate(_ctx(Action.Mint, msg.sender, address(0), to, amount));

        uint256 toBalance = _balances[to];
        _totalSupply += amount;
        unchecked {
            _balances[to] = toBalance + amount;
        }
        if (amount > 0 && toBalance == 0) ++_holderCount;

        emit Transfer(address(0), to, amount);

        // A minted balance is a receipt, so the MinHoldTime clock must start
        // here too. Without this, mint-then-transfer walks straight past a hold
        // period that a transfer between holders would have to respect.
        _policy.recordTransfer(_ctx(Action.Mint, msg.sender, address(0), to, amount));
    }

    /// @notice Destroy some of the caller's own balance.
    /// @dev There is deliberately no admin path to burn someone else's tokens.
    ///      See the contract NatSpec: confiscation is a strictly stronger power
    ///      than the freeze this design refuses to implement, so accepting one
    ///      while rejecting the other would be incoherent. Burning sits outside
    ///      the policy because it moves nothing to anyone — it cannot be used
    ///      to escape a lockup, only to give up value.
    function burn(uint256 amount) external {
        uint256 fromBalance = _balances[msg.sender];
        if (fromBalance < amount) revert InsufficientBalance();

        _gate(_ctx(Action.Burn, msg.sender, msg.sender, address(0), amount));

        unchecked {
            _balances[msg.sender] = fromBalance - amount;
            _totalSupply -= amount;
        }
        if (amount > 0 && fromBalance == amount) --_holderCount;

        emit Transfer(msg.sender, address(0), amount);
    }
}
