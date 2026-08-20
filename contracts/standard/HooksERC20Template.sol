//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./IHooksERC20.sol";

/**
 * @title HooksERC20Template
 * @notice DRAFT — minimal starting point for an IHooksERC20-conforming contract,
 *         deliberately decoupled from this repo's own token/admin machinery.
 *         Copy this file and override the `_on*` hooks; everything else is
 *         boilerplate you get for free (ERC-165, the CALL-only access gate, the
 *         one-time init step).
 *
 * DEPLOYMENT ORDERING: a hooks contract and its token typically need each other's
 * address, but only one can be deployed first. This template resolves that with a
 * one-time `initialize(token)` call gated by `owner`. This repo's own production
 * `HooksERC20` solves the same problem differently — its constructor deploys its
 * token directly via `new`, since it always knows the concrete token type at
 * compile time, which a template kept deliberately generic cannot assume — but
 * the interface itself doesn't mandate either approach; use whichever init story
 * fits your deployment flow.
 *
 *   1. Deploy MyHooks(msg.sender) — owner is set, token is not yet known.
 *   2. Deploy the token, passing MyHooks' address as its immutable hooks address.
 *   3. Call MyHooks.initialize(tokenAddress) as owner, once.
 */
abstract contract HooksERC20Template is IHooksERC20, ERC165 {
    address public owner;
    address public token;
    bool private _initialized;

    modifier onlyToken() {
        require(msg.sender == token, "Hooks: caller is not the token");
        _;
    }

    constructor(address _owner) {
        require(_owner != address(0), "Hooks: zero owner");
        owner = _owner;
    }

    /// @notice One-time wiring of the token this hooks contract governs.
    function initialize(address _token) external {
        require(msg.sender == owner, "Hooks: not owner");
        require(!_initialized, "Hooks: already initialized");
        require(_token != address(0), "Hooks: zero token");
        token = _token;
        _initialized = true;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC20).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 amount) external onlyToken {
        _onBeforeTransfer(from, to, amount);
    }

    /// @dev Override for custom pre-transfer logic. Revert to block (fail-closed).
    function _onBeforeTransfer(address from, address to, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 amount)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateTransfer(from, to, amount);
    }

    /// @dev Override to deny. Default: always allow.
    function _onValidateTransfer(address from, address to, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 amount) external onlyToken {
        _onAfterTransfer(from, to, amount);
    }

    /// @dev Informational only — the host try/catch-wraps this call.
    function _onAfterTransfer(address from, address to, uint256 amount) internal virtual {}

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 amount) external onlyToken {
        _onBeforeMint(to, amount);
    }

    function _onBeforeMint(address to, uint256 amount) internal virtual {}

    function validateMint(address to, uint256 amount)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateMint(to, amount);
    }

    function _onValidateMint(address to, uint256 amount) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterMint(address to, uint256 amount) external onlyToken {
        _onAfterMint(to, amount);
    }

    function _onAfterMint(address to, uint256 amount) internal virtual {}

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 amount) external onlyToken {
        _onBeforeBurn(from, amount);
    }

    function _onBeforeBurn(address from, uint256 amount) internal virtual {}

    function validateBurn(address from, uint256 amount)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateBurn(from, amount);
    }

    function _onValidateBurn(address from, uint256 amount) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 amount) external onlyToken {
        _onAfterBurn(from, amount);
    }

    function _onAfterBurn(address from, uint256 amount) internal virtual {}
}
