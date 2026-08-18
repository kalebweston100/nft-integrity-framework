// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/interfaces/Errors.sol";

/// @notice Exercises the shared FactoryBase surface (deploy fees, withdrawals,
///         ownership, chain-of-trust verification, bytecode-hash verification)
///         through the concrete FactoryERC721. FactoryBase has no per-standard
///         behavior, so testing it once here covers FactoryERC20/1155 as well.
contract FactoryBaseTest is Fixtures {
    address internal issuer = makeAddr("issuer");
    address internal stranger = makeAddr("stranger");

    // ─── Deploy fee ──────────────────────────────────────────────────────────

    function test_deployFee_defaultsToZero() public {
        FactoryERC721 factory = new FactoryERC721();
        assertEq(factory.deployFee(), 0);
    }

    function test_deployFee_onlyOwnerCanSet() public {
        FactoryERC721 factory = new FactoryERC721();
        vm.prank(stranger);
        vm.expectRevert(NotOwner.selector);
        factory.setDeployFee(1 ether);
    }

    function test_deployToken_revertsIfFeeNotMet() public {
        FactoryERC721 factory = new FactoryERC721();
        factory.setDeployFee(1 ether);

        vm.expectRevert(InsufficientDeployFee.selector);
        factory.deployTokenERC721(issuer, address(0), "N", "S", "uri", "base/");
    }

    function test_deployToken_succeedsAndAccumulatesFee() public {
        FactoryERC721 factory = new FactoryERC721();
        factory.setDeployFee(1 ether);

        address token = factory.deployTokenERC721{value: 1 ether}(issuer, address(0), "N", "S", "uri", "base/");

        assertTrue(token != address(0));
        assertEq(factory.feeBalance(), 1 ether);
    }

    function test_withdrawFees_onlyOwner() public {
        FactoryERC721 factory = new FactoryERC721();
        factory.setDeployFee(1 ether);
        factory.deployTokenERC721{value: 1 ether}(issuer, address(0), "N", "S", "uri", "base/");

        vm.prank(stranger);
        vm.expectRevert(NotOwner.selector);
        factory.withdrawFees(stranger);
    }

    function test_withdrawFees_revertsWhenNothingToWithdraw() public {
        FactoryERC721 factory = new FactoryERC721();
        vm.expectRevert(NothingToWithdraw.selector);
        factory.withdrawFees(address(this));
    }

    function test_withdrawFees_transfersBalanceAndResets() public {
        FactoryERC721 factory = new FactoryERC721();
        factory.setDeployFee(1 ether);
        factory.deployTokenERC721{value: 1 ether}(issuer, address(0), "N", "S", "uri", "base/");

        address payable recipient = payable(makeAddr("recipient"));
        factory.withdrawFees(recipient);

        assertEq(recipient.balance, 1 ether);
        assertEq(factory.feeBalance(), 0);
    }

    // ─── Ownership ───────────────────────────────────────────────────────────

    function test_transferOwnership_onlyOwner() public {
        FactoryERC721 factory = new FactoryERC721();
        vm.prank(stranger);
        vm.expectRevert(NotOwner.selector);
        factory.transferOwnership(stranger);
    }

    function test_transferOwnership_rejectsZeroAddress() public {
        FactoryERC721 factory = new FactoryERC721();
        vm.expectRevert(ZeroAddress.selector);
        factory.transferOwnership(address(0));
    }

    function test_transferOwnership_updatesOwner() public {
        FactoryERC721 factory = new FactoryERC721();
        factory.transferOwnership(stranger);
        assertEq(factory.owner(), stranger);
    }

    // ─── Chain of trust ──────────────────────────────────────────────────────

    function test_verifyChainOfTrust_trueForGenuineDeployment() public {
        (FactoryERC721 factory,, IntegrityERC721 token) = _deployERC721(issuer);
        assertTrue(factory.verifyChainOfTrust(address(token)));
    }

    function test_verifyChainOfTrust_falseForUnknownToken() public {
        FactoryERC721 factory = new FactoryERC721();
        assertFalse(factory.verifyChainOfTrust(address(0xBEEF)));
    }

    function test_verifyChainOfTrust_falseAcrossDifferentFactories() public {
        // A token deployed by factory A is not part of factory B's chain of trust,
        // even though both run byte-identical canonical code.
        (,, IntegrityERC721 token) = _deployERC721(issuer);
        FactoryERC721 otherFactory = new FactoryERC721();
        assertFalse(otherFactory.verifyChainOfTrust(address(token)));
    }

    // ─── Bytecode hash verification ─────────────────────────────────────────

    function test_isCanonicalCodeHash_matchesAcrossIndependentDeployments() public {
        // FactoryBase and its concrete subclasses hold no immutable state, so two
        // independent deployments of the same factory produce identical runtime
        // bytecode/hash regardless of deployer or constructor-time owner.
        FactoryERC721 factoryA = new FactoryERC721();
        vm.prank(stranger);
        FactoryERC721 factoryB = new FactoryERC721();

        assertEq(factoryA.runtimeCodeHash(), factoryB.runtimeCodeHash());
        assertTrue(factoryA.isCanonicalCodeHash(address(factoryB), factoryA.runtimeCodeHash()));
    }

    function test_isCanonicalCodeHash_falseForDifferentBytecode() public {
        FactoryERC721 factory = new FactoryERC721();
        (,, IntegrityERC721 token) = _deployERC721(issuer);

        assertFalse(factory.isCanonicalCodeHash(address(token), factory.runtimeCodeHash()));
    }

    function test_isCanonicalCodeHash_neverCallsIntoTarget() public {
        // A target with no code at all must simply fail the comparison, not revert —
        // proving the check is a pure EXTCODEHASH read with no external call.
        FactoryERC721 factory = new FactoryERC721();
        assertFalse(factory.isCanonicalCodeHash(address(0xDEAD), factory.runtimeCodeHash()));
    }
}
