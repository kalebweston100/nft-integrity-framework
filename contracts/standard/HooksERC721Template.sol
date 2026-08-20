//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./IHooksERC721.sol";

/**
 * @title HooksERC721Template
 * @notice DRAFT — minimal starting point for an IHooksERC721-conforming contract.
 *         See HooksERC20Template for the full explanation of the deployment-ordering
 *         and access-control pattern used here; this is the same shape applied to
 *         ERC-721's (address, address, tokenId) signatures.
 */
abstract contract HooksERC721Template is IHooksERC721, ERC165 {
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

    function initialize(address _token) external {
        require(msg.sender == owner, "Hooks: not owner");
        require(!_initialized, "Hooks: already initialized");
        require(_token != address(0), "Hooks: zero token");
        token = _token;
        _initialized = true;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC721).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 tokenId) external onlyToken {
        _onBeforeTransfer(from, to, tokenId);
    }

    function _onBeforeTransfer(address from, address to, uint256 tokenId) internal virtual {}

    function validateTransfer(address from, address to, uint256 tokenId)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateTransfer(from, to, tokenId);
    }

    function _onValidateTransfer(address from, address to, uint256 tokenId)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 tokenId) external onlyToken {
        _onAfterTransfer(from, to, tokenId);
    }

    function _onAfterTransfer(address from, address to, uint256 tokenId) internal virtual {}

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 tokenId) external onlyToken {
        _onBeforeMint(to, tokenId);
    }

    function _onBeforeMint(address to, uint256 tokenId) internal virtual {}

    function validateMint(address to, uint256 tokenId)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateMint(to, tokenId);
    }

    function _onValidateMint(address to, uint256 tokenId) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterMint(address to, uint256 tokenId) external onlyToken {
        _onAfterMint(to, tokenId);
    }

    function _onAfterMint(address to, uint256 tokenId) internal virtual {}

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 tokenId) external onlyToken {
        _onBeforeBurn(from, tokenId);
    }

    function _onBeforeBurn(address from, uint256 tokenId) internal virtual {}

    function validateBurn(address from, uint256 tokenId)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateBurn(from, tokenId);
    }

    function _onValidateBurn(address from, uint256 tokenId) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 tokenId) external onlyToken {
        _onAfterBurn(from, tokenId);
    }

    function _onAfterBurn(address from, uint256 tokenId) internal virtual {}
}
