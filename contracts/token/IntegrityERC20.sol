//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "./IntegrityTokenBase.sol";
import "../hooks/HooksWrapperERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IntegrityERC20
 * @notice The user-facing ERC-20 token contract. Users call transfer(),
 *         approve(), etc. directly on this contract, which holds all state
 *         and the full locked transfer pipeline, and delegates policy
 *         decisions to an external wrapper contract.
 *
 * ARCHITECTURE: this contract IS the token — all balances, allowances, and
 * admin state live here. Developers customize behavior by inheriting
 * HooksLogicERC20, whose constructor deploys a HooksWrapperERC20, which
 * deploys THIS contract via `new` and wires itself as governor — no factory,
 * no separate registration step. Inherits IntegrityTokenBase (reentrancy
 * guard, IIntegrityToken) and, via it, TokenAdmin (issuer admin,
 * pause/unpause).
 *
 * SECURITY:
 *   - transfer/transferFrom/approve are non-virtual; the pipeline is
 *     non-overridable (this contract is not abstract)
 *   - The wrapper is called via external CALL and cannot access token
 *     storage; nothing on the hooks side can ever call back into this
 *     contract. Mint and burn are exclusively issuer-admin-gated,
 *     unconditionally.
 *   - Wrapper address is read from msg.sender at construction and stored in a
 *     plain, setter-less slot — never immutable, so this contract's runtime
 *     bytecode stays byte-identical across every deployment. See
 *     IntegrityVerifier.sol.
 *   - Strict ERC-20 superset: zero-value transfers succeed, as required.
 */
contract IntegrityERC20 is IERC20, IntegrityTokenBase {
    // =========================================================================
    //                          EVENTS
    // =========================================================================

    event HookCallFailed(string hookName, bytes reason);

    // =========================================================================
    //                     WRAPPER CONTRACT (plain storage, setter-less)
    // =========================================================================

    /// @notice The wrapper that deployed and governs this token. Never
    ///         address(0). Deliberately not `immutable`: see contract NatSpec.
    HooksWrapperERC20 private _hooks;

    // =========================================================================
    //                     TOKEN STORAGE
    // =========================================================================

    string private _name;
    string private _symbol;
    uint8 public constant decimals = 18;
    uint256 private _totalSupply;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    /// @notice Deployed by its own wrapper, via `new`, from inside that
    ///         contract's constructor.
    constructor(address admin, string memory tokenName, string memory tokenSymbol, string memory initialContractURI)
        IntegrityTokenBase(admin, initialContractURI)
    {
        _hooks = HooksWrapperERC20(msg.sender);
        _name = tokenName;
        _symbol = tokenSymbol;
    }

    // =========================================================================
    //                     CHAIN-OF-TRUST GETTERS
    // =========================================================================

    function hooksContract() external view returns (address) {
        return address(_hooks);
    }

    // =========================================================================
    //                  ERC-20 ENTRY POINTS (non-virtual, locked)
    // =========================================================================

    function transfer(address to, uint256 amount) external override whenNotPaused nonReentrant returns (bool) {
        _transferPipeline(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        override
        whenNotPaused
        nonReentrant
        returns (bool)
    {
        uint256 currentAllowance = _allowances[from][msg.sender];
        if (currentAllowance < amount) revert InsufficientAllowance();
        _allowances[from][msg.sender] = currentAllowance - amount;
        _transferPipeline(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        if (spender == address(0)) revert ZeroAddress();
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// @notice Atomically increase the allowance granted to a spender.
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        if (spender == address(0)) revert ZeroAddress();
        _allowances[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, _allowances[msg.sender][spender]);
        return true;
    }

    /// @notice Atomically decrease the allowance granted to a spender.
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        if (spender == address(0)) revert ZeroAddress();
        uint256 currentAllowance = _allowances[msg.sender][spender];
        if (currentAllowance < subtractedValue) revert InsufficientAllowance();
        _allowances[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, _allowances[msg.sender][spender]);
        return true;
    }

    // =========================================================================
    //                   TRANSFER PIPELINE (private, locked)
    // =========================================================================

    /// @dev Zero-value transfers are permitted and emit Transfer, per ERC-20.
    function _transferPipeline(address from, address to, uint256 amount) private {
        // [LOCKED] Sufficient balance check
        if (_balances[from] < amount) revert InsufficientBalance();
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Settle-only notification, then the authoritative
        // deny gate. A hook can refuse here; it can never write token storage.
        _hooks.beforeTransfer(from, to, amount);
        (bool valid, string memory reason) = _hooks.validateTransfer(from, to, amount);
        require(valid, reason);

        // [LOCKED] Balance mutation
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);

        // [HOOKS - external call, safe] Developer's post-transfer logic
        try _hooks.afterTransfer(from, to, amount) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterTransfer", failReason);
        }
    }

    // =========================================================================
    //                     ISSUER ADMIN: MINT / BURN
    // =========================================================================

    /// @notice Mint tokens. Only callable by issuer admin. This is the ONLY way
    ///         supply can ever increase — there is no hook-initiated mint path.
    /// @param to Recipient address.
    /// @param amount Token amount to mint.
    /// @param data Arbitrary data forwarded to hooks.
    function mint(address to, uint256 amount, bytes calldata data) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-mint logic
        (bool allowed, string memory reason) = _hooks.beforeMint(to, amount, data);
        require(allowed, reason);

        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);

        // [HOOKS - external call, safe] Developer's post-mint logic
        try _hooks.afterMint(to, amount, data) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterMint", failReason);
        }
    }

    /// @notice Burn tokens. Only callable by issuer admin.
    function burn(address from, uint256 amount) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (_balances[from] < amount) revert InsufficientBalance();

        // [HOOKS - external call] Developer's pre-burn logic
        (bool allowed, string memory reason) = _hooks.beforeBurn(from, amount);
        require(allowed, reason);

        _balances[from] -= amount;
        _totalSupply -= amount;
        emit Transfer(from, address(0), amount);

        // [HOOKS - external call, safe] Developer's post-burn logic
        try _hooks.afterBurn(from, amount) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterBurn", failReason);
        }
    }

    // =========================================================================
    //                          VIEW FUNCTIONS
    // =========================================================================

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) external view override returns (uint256) {
        return _allowances[owner][spender];
    }

    // =========================================================================
    //                     ERC165 INTERFACE SUPPORT
    // =========================================================================

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC20).interfaceId || interfaceId == type(IIntegrityToken).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // =========================================================================
    //                     IIntegrityToken: tokenStandard
    // =========================================================================

    function tokenStandard() external pure override returns (TokenStandard) {
        return TokenStandard.ERC20;
    }

    // =========================================================================
    //                     canTransfer (read-only check)
    // =========================================================================

    /// @notice Checks whether a transfer would be allowed without executing it.
    function canTransfer(address from, address to, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (_isPaused()) return (false, "Token is paused");
        if (_balances[from] < amount) return (false, "Insufficient balance");
        if (to == address(0)) return (false, "Zero recipient");
        (bool valid, string memory validationReason) = _hooks.validateTransfer(from, to, amount);
        if (!valid) return (false, validationReason);
        return (true, "");
    }
}
