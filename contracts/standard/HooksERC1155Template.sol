//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./IHooksERC1155.sol";

/**
 * @title HooksERC1155Template
 * @notice DRAFT — minimal starting point for an IHooksERC1155-conforming contract.
 *         See HooksERC20Template for the deployment-ordering / access-control pattern.
 *         This template implements the single-item path with real logic and reverts
 *         from the batch path by default (`supportsBatch() == false`) — override the
 *         batch `_on*` hooks and flip `_batchSupported` if your token issues batches.
 */
abstract contract HooksERC1155Template is IHooksERC1155, ERC165 {
    address public owner;
    address public token;
    bool private _initialized;
    bool internal _batchSupported = false;

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
        return interfaceId == type(IHooksERC1155).interfaceId || super.supportsInterface(interfaceId);
    }

    function supportsBatch() external view returns (bool) {
        return _batchSupported;
    }

    // =========================================================================
    //                          TRANSFER (single)
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external onlyToken {
        _onBeforeTransfer(from, to, id, amount);
    }

    function _onBeforeTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateTransfer(from, to, id, amount);
    }

    function _onValidateTransfer(address from, address to, uint256 id, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external onlyToken {
        _onAfterTransfer(from, to, id, amount);
    }

    function _onAfterTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                          TRANSFER (batch)
    // =========================================================================

    function beforeBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        external
        onlyToken
    {
        require(_batchSupported, "Hooks: batch not supported");
        _onBeforeBatchTransfer(from, to, ids, amounts);
    }

    function _onBeforeBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        internal
        virtual {}

    function validateBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        require(_batchSupported, "Hooks: batch not supported");
        return _onValidateBatchTransfer(from, to, ids, amounts);
    }

    function _onValidateBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        external
        onlyToken
    {
        require(_batchSupported, "Hooks: batch not supported");
        _onAfterBatchTransfer(from, to, ids, amounts);
    }

    function _onAfterBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        internal
        virtual {}

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 id, uint256 amount) external onlyToken {
        _onBeforeMint(to, id, amount);
    }

    function _onBeforeMint(address to, uint256 id, uint256 amount) internal virtual {}

    function validateMint(address to, uint256 id, uint256 amount)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateMint(to, id, amount);
    }

    function _onValidateMint(address to, uint256 id, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint(address to, uint256 id, uint256 amount) external onlyToken {
        _onAfterMint(to, id, amount);
    }

    function _onAfterMint(address to, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 id, uint256 amount) external onlyToken {
        _onBeforeBurn(from, id, amount);
    }

    function _onBeforeBurn(address from, uint256 id, uint256 amount) internal virtual {}

    function validateBurn(address from, uint256 id, uint256 amount)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateBurn(from, id, amount);
    }

    function _onValidateBurn(address from, uint256 id, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterBurn(address from, uint256 id, uint256 amount) external onlyToken {
        _onAfterBurn(from, id, amount);
    }

    function _onAfterBurn(address from, uint256 id, uint256 amount) internal virtual {}
}
