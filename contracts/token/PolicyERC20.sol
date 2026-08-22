//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";

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
 *      zero immutables and is not abstract, not virtual, and not upgradeable.
 *
 *   2. THE POLICY IS CANONICAL. `_policy` is deployed by THIS contract's
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
 * MINT AND BURN ARE OUTSIDE THE POLICY
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Both are onlyIssuerAdmin, unconditionally, so the issuer already has complete
 * control over supply and routing them through the policy would add nothing a
 * holder can rely on. The claim above is scoped to transfers, and says so.
 * Running mint through LockupUntil would also make initial distribution
 * impossible.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ZERO IMMUTABLES — LOAD-BEARING
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * `_policy`, `_issuerAdmin` and `_deployAdmin` are plain storage written once
 * in the constructor with no setter. POLICY_SALT is `constant`, which inlines
 * into bytecode and — unlike `immutable` — does not break
 * type(PolicyERC20).runtimeCode. Adding one immutable stops the verifier
 * compiling; the constraint enforces itself. See contracts/verification/CanonicalCode.sol.
 */
contract PolicyERC20 {
    // =========================================================================
    //                              ERRORS / EVENTS
    // =========================================================================

    /// @notice The policy denied this transfer, and named the rule that did.
    error PolicyDenied(string reason);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event IssuerAdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // =========================================================================
    //                                CONSTANTS
    // =========================================================================

    /// @dev `constant`, not `immutable` — inlined into bytecode, so
    ///      type(PolicyERC20).runtimeCode still compiles.
    bytes32 private constant POLICY_SALT = keccak256("PolicyERC20.policy.v1");

    uint8 public constant decimals = 18;

    // =========================================================================
    //                        STATE — ALL PLAIN STORAGE
    // =========================================================================

    /// @notice The canonical engine holding this token's complete transfer
    ///         policy. Deployed by this contract's constructor via CREATE2.
    ///         No setter exists.
    PolicyEngine private _policy;

    address private _issuerAdmin;

    /// @notice The admin passed to the constructor, recorded once and never
    ///         changed. Needed to recompute this token's CREATE2 address after
    ///         an admin handover — see CanonicalCode.isProvenanceVerified.
    address private _deployAdmin;

    string private _name;
    string private _symbol;
    uint256 private _totalSupply;

    /// @notice Count of addresses holding a non-zero balance. Maintained here
    ///         because the HolderCap rule needs it and no ERC-20 exposes it;
    ///         the policy is never permitted to call back to fetch it.
    uint256 private _holderCount;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // =========================================================================
    //                                MODIFIERS
    // =========================================================================

    modifier onlyIssuerAdmin() {
        if (msg.sender != _issuerAdmin) revert NotIssuerAdmin();
        _;
    }

    // =========================================================================
    //                               CONSTRUCTOR
    // =========================================================================

    /// @notice One transaction deploys the token and its policy together. There
    ///         is no initializer and therefore no window in which this token
    ///         exists with no policy attached.
    /// @dev    The engine needs its notifier (this token) and this token needs
    ///         the engine's address — a cycle at the value level, but not at
    ///         the TYPE level, which is what matters to the compiler.
    ///         PolicyEngine imports only PolicyTypes and never names this
    ///         contract, so the code dependency graph stays acyclic and
    ///         type(PolicyEngine).creationCode resolves here.
    /// @param admin      Issuer admin: may mint, burn, and change policy rules.
    /// @param tokenName  ERC-20 name.
    /// @param tokenSymbol ERC-20 symbol.
    /// @param swapDelay  Seconds of public notice before any rule change commits.
    /// @param initialRules The token's policy at launch. May be empty.
    constructor(
        address admin,
        string memory tokenName,
        string memory tokenSymbol,
        uint256 swapDelay,
        Rule[] memory initialRules
    ) {
        if (admin == address(0)) revert ZeroAddress();

        _issuerAdmin = admin;
        _deployAdmin = admin;
        _name = tokenName;
        _symbol = tokenSymbol;

        _policy = new PolicyEngine{salt: POLICY_SALT}(admin, address(this), swapDelay, initialRules);
    }

    // =========================================================================
    //                        THE INTEGRATOR SURFACE
    // =========================================================================

    /// @notice The engine holding this token's complete transfer policy.
    /// @dev    Check its codehash against keccak256(type(PolicyEngine).runtimeCode)
    ///         before trusting anything it returns, then read rules() off it.
    ///         Because THIS contract's code is canonical, the getter and the
    ///         caller in _transfer() read the same setter-less slot.
    function policy() external view returns (address) {
        return address(_policy);
    }

    function tokenStandard() external pure returns (TokenStandard) {
        return TokenStandard.ERC20;
    }

    /// @notice Number of addresses holding a non-zero balance.
    function holderCount() external view returns (uint256) {
        return _holderCount;
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

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    /// @notice Whether the policy would currently allow this transfer, and why
    ///         not if it would not. Free to call; changes nothing.
    function canTransfer(address from, address to, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (to == address(0)) return (false, "zero recipient");
        if (_balances[from] < amount) return (false, "insufficient balance");
        return _policy.evaluate(_context(from, to, amount));
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

    function approve(address spender, uint256 amount) external returns (bool) {
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
        (bool ok, string memory reason) = _policy.evaluate(_context(from, to, amount));
        if (!ok) revert PolicyDenied(reason);

        // [LOCKED] Balance mutation. Nothing above this line has written state,
        // so the balances the policy saw are the pre-transfer values its
        // TransferContext documentation promises.
        _moveBalance(from, to, amount);

        emit Transfer(from, to, amount);

        // [POST-TRANSFER] Lets stateful rules (MinHoldTime) record what settled.
        // Gated to this token as `notifier` on the engine. The engine is
        // canonical, so this is not an untrusted call and needs no try/catch:
        // its only write is lastReceived, and a revert here can only mean a bug
        // in code the verifier has already checked.
        _policy.recordTransfer(_context(from, to, amount));
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
    function _context(address from, address to, uint256 amount) private view returns (TransferContext memory) {
        return TransferContext({
            standard: TokenStandard.ERC20,
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
    //                        SUPPLY — ISSUER ADMIN ONLY
    // =========================================================================

    /// @notice Mint new supply. Unconditionally issuer-admin gated; see the
    ///         contract NatSpec for why this is outside the policy.
    function mint(address to, uint256 amount) external onlyIssuerAdmin {
        if (to == address(0)) revert ZeroAddress();

        uint256 toBalance = _balances[to];
        _totalSupply += amount;
        unchecked {
            _balances[to] = toBalance + amount;
        }
        if (amount > 0 && toBalance == 0) ++_holderCount;

        emit Transfer(address(0), to, amount);
    }

    /// @notice Burn supply from an address. Unconditionally issuer-admin gated.
    function burn(address from, uint256 amount) external onlyIssuerAdmin {
        uint256 fromBalance = _balances[from];
        if (fromBalance < amount) revert InsufficientBalance();

        unchecked {
            _balances[from] = fromBalance - amount;
            _totalSupply -= amount;
        }
        if (amount > 0 && fromBalance == amount) --_holderCount;

        emit Transfer(from, address(0), amount);
    }

    // =========================================================================
    //                                  ADMIN
    // =========================================================================

    function issuerAdmin() external view returns (address) {
        return _issuerAdmin;
    }

    /// @notice The admin recorded at deployment. Never changes, even after a
    ///         handover — needed to recompute this token's CREATE2 address.
    function deployAdmin() external view returns (address) {
        return _deployAdmin;
    }

    /// @dev Moves the token's admin only. The engine holds its own admin, set
    ///      to the same address at construction; transferring one does not move
    ///      the other, and a verifier reports both.
    function transferIssuerAdmin(address newAdmin) external onlyIssuerAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit IssuerAdminTransferred(_issuerAdmin, newAdmin);
        _issuerAdmin = newAdmin;
    }
}
