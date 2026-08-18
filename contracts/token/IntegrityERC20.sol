//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "./IntegrityTokenBase.sol";
import "../hooks/HooksERC20.sol";
import "../interfaces/IHooks.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IntegrityERC20
 * @notice The user-facing ERC-20 token contract. Users call transfer(),
 *         approve(), etc. directly on this contract. Contains ALL token
 *         storage, the full locked transfer pipeline, AND delegates to an
 *         external developer-deployed hooks contract for custom logic.
 *
 * ARCHITECTURE:
 *   This contract IS the token. It holds all state (balances, allowances,
 *   holder tracking, admin state) and contains the full transfer pipeline.
 *   Developers customize behavior by deploying a separate hooks contract
 *   implementing ITokenHooks. The token calls hooks via external call — the
 *   hooks contract has its own storage and CANNOT access or modify token state.
 *
 * INHERITS:
 *   IntegrityTokenBase — factory immutable, reentrancy guard, chain-of-trust
 *     getters, IIntegrityToken partial implementation
 *   TokenAdmin (via Base) — issuer admin, pause/unpause
 *
 * DEPLOYMENT:
 *   1. Developer deploys their hooks contract (implements ITokenHooks)
 *   2. Developer calls factory.deployTokenERC20(hooksAddress, ...)
 *   3. Factory deploys this IntegrityERC20 with the hooks address
 *   4. Factory registers the token
 *   5. Users interact with THIS contract for all ERC-20 operations
 *
 * CHAIN OF TRUST:
 *   1. token.factory()        → immutable deploying factory
 *   2. token.hooksContract()  → immutable developer hooks (address(0) if none)
 *   3. factory.deployedByFactory(token) → confirms factory deployment
 *   Anyone can verify the full trust chain via these public getters.
 *
 * SECURITY:
 *   - Deployed exclusively by the factory via `new`
 *   - transfer(), transferFrom(), approve() are non-virtual (concrete contract)
 *   - Transfer pipeline is non-overridable (this contract is not abstract)
 *   - Hooks run via external call — cannot access token storage
 *   - Hooks can only ADD restrictions (revert/return false), not bypass checks
 *   - Hooks address is immutable — set at deployment, cannot be changed
 *   - address(0) hooks = no custom logic, plain token
 */
contract IntegrityERC20 is IERC20, IHookMintERC20, IntegrityTokenBase {
    // =========================================================================
    //                          EVENTS
    // =========================================================================

    // Token-specific events (ERC20 events inherited from IERC20)
    event HolderAdded(address indexed holder, uint256 holderCount);
    event HolderRemoved(address indexed holder, uint256 holderCount);
    event TransferBlocked(address indexed from, address indexed to, uint256 amount, string reason);
    event HookCallFailed(string hookName, bytes reason);

    // =========================================================================
    //                     HOOKS CONTRACT (immutable)
    // =========================================================================

    /// @notice The developer's hooks contract. address(0) = no hooks.
    /// @dev Immutable — set at deployment, cannot be changed.
    HooksERC20Base private immutable _hooks;

    /// @notice Whether a hooks contract is set (cached to avoid repeated address(0) checks).
    bool private immutable _hasHooks;

    // =========================================================================
    //                     TOKEN STORAGE
    // =========================================================================

    string private _name;
    string private _symbol;
    uint8 public constant decimals = 18;
    uint256 private _totalSupply;
    uint256 private _holderCount;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(address => uint256) private _firstReceivedAt;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    /// @notice Deployed by the TokenFactory.
    /// @param factoryAddr The deploying factory address.
    /// @param hooksAddr The developer's hooks contract (address(0) for no hooks).
    /// @param admin The initial issuer admin address.
    /// @param tokenName The token's display name.
    /// @param tokenSymbol The token's ticker symbol.
    constructor(
        address factoryAddr,
        address hooksAddr,
        address admin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory initialContractURI
    ) IntegrityTokenBase(factoryAddr, admin, initialContractURI) {
        _hooks = HooksERC20Base(hooksAddr);
        _hasHooks = hooksAddr != address(0);
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

    /// @notice Transfer tokens.
    function transfer(address to, uint256 amount) external override whenNotPaused nonReentrant returns (bool) {
        _transferPipeline(msg.sender, to, amount);
        return true;
    }

    /// @notice Transfer tokens on behalf of another address.
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

    /// @notice Approve a spender.
    function approve(address spender, uint256 amount) external override returns (bool) {
        if (msg.sender == address(0)) revert ZeroAddress();
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

    function _transferPipeline(address from, address to, uint256 amount) private {
        // [LOCKED] Sufficient balance check
        if (amount == 0) revert ZeroAmount();
        if (_balances[from] < amount) revert InsufficientBalance();
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-transfer and validation logic
        if (_hasHooks) {
            _hooks.beforeTransfer(from, to, amount);
            (bool valid, string memory reason) = _hooks.validateTransfer(from, to, amount);
            require(valid, reason);
        }

        // [LOCKED] Balance mutation
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);

        // [LOCKED] Holder tracking
        if (_firstReceivedAt[to] == 0) {
            _firstReceivedAt[to] = block.timestamp;
            _holderCount++;
            emit HolderAdded(to, _holderCount);
        }
        if (_balances[from] == 0) {
            delete _firstReceivedAt[from];
            _holderCount--;
            emit HolderRemoved(from, _holderCount);
        }

        // [HOOKS - external call, safe] Developer's post-transfer logic
        if (_hasHooks) {
            try _hooks.afterTransfer(from, to, amount) {}
            catch (bytes memory reason) {
                emit HookCallFailed("afterTransfer", reason);
            }
        }
    }

    // =========================================================================
    //                     ISSUER ADMIN: MINT / BURN
    // =========================================================================

    /// @notice Mint tokens. Only callable by issuer admin.
    /// @param to Recipient address.
    /// @param amount Token amount to mint.
    /// @param data Arbitrary data forwarded to hooks (e.g., payment info, listing key).
    function mint(address to, uint256 amount, bytes calldata data) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-mint logic
        if (_hasHooks) {
            (bool allowed, string memory reason) = _hooks.beforeMint(to, amount, data);
            require(allowed, reason);
        }

        bool wasNewHolder = (_balances[to] == 0);

        _totalSupply += amount;
        _balances[to] += amount;

        emit Transfer(address(0), to, amount);

        if (wasNewHolder && _balances[to] > 0) {
            _firstReceivedAt[to] = block.timestamp;
            _holderCount++;
            emit HolderAdded(to, _holderCount);
        }

        // [HOOKS - external call, safe] Developer's post-mint logic
        if (_hasHooks) {
            try _hooks.afterMint(to, amount, data) {}
            catch (bytes memory reason) {
                emit HookCallFailed("afterMint", reason);
            }
        }
    }

    /// @notice Burn tokens with holder tracking. Only callable by issuer admin.
    function burn(address from, uint256 amount) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (_balances[from] < amount) revert InsufficientBalance();

        // [HOOKS - external call] Developer's pre-burn logic
        if (_hasHooks) {
            (bool allowed, string memory reason) = _hooks.beforeBurn(from, amount);
            require(allowed, reason);
        }

        _balances[from] -= amount;
        _totalSupply -= amount;
        emit Transfer(from, address(0), amount);

        if (_balances[from] == 0) {
            delete _firstReceivedAt[from];
            _holderCount--;
            emit HolderRemoved(from, _holderCount);
        }

        // [HOOKS - external call, safe] Developer's post-burn logic
        if (_hasHooks) {
            try _hooks.afterBurn(from, amount) {}
            catch (bytes memory reason) {
                emit HookCallFailed("afterBurn", reason);
            }
        }
    }

    // =========================================================================
    //                     HOOKS-INITIATED MINT (no beforeMint/afterMint)
    // =========================================================================

    /// @notice Mint tokens initiated by the hooks contract. Skips beforeMint/afterMint
    ///         callbacks to avoid circular calls.
    /// @dev Only callable by the hooks contract. Reverts if no hooks contract is set.
    /// @param to Recipient address.
    /// @param amount Token amount to mint.
    function hookMint(address to, uint256 amount) external override whenNotPaused nonReentrant {
        if (!_hasHooks || msg.sender != address(_hooks)) revert NotHooksContract();
        if (to == address(0)) revert ZeroAddress();

        bool wasNewHolder = (_balances[to] == 0);

        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);

        if (wasNewHolder && _balances[to] > 0) {
            _firstReceivedAt[to] = block.timestamp;
            _holderCount++;
            emit HolderAdded(to, _holderCount);
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

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) external view override returns (uint256) {
        return _allowances[owner][spender];
    }

    function holderCount() external view returns (uint256) {
        return _holderCount;
    }

    function firstReceivedAt(address account) external view returns (uint256) {
        return _firstReceivedAt[account];
    }

    // =========================================================================
    //                     ERC165 INTERFACE SUPPORT
    // =========================================================================

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC20).interfaceId || interfaceId == type(IIntegrityToken).interfaceId
            || interfaceId == 0x01ffc9a7; // ERC165
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
        if (_hasHooks) {
            (bool valid, string memory validationReason) = _hooks.validateTransfer(from, to, amount);
            if (!valid) return (false, validationReason);
        }
        return (true, "");
    }
}
