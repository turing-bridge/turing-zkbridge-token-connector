// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "./AdminControlled.sol";

// Uncomment this line to use console.log
// import "hardhat/console.sol";

contract Locker is AdminControlled {
    address payable public owner;
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    event Locked(
        address indexed token,
        address indexed sender,
        uint256 amount,
        string accountId
    );

    event Unlocked(uint128 amount, address recipient);

    // Function output from burning fungible token on the other chain.
    struct BurnResult {
        uint128 amount;
        address token;
        address recipient;
    }

    /// Proofs from blocks that are below the acceptance height will be rejected.
    // If `minBlockAcceptanceHeight` value is zero - proofs from block with any height are accepted.
    uint64 public minBlockAcceptanceHeight;

    uint constant UNPAUSED_ALL = 0;
    uint constant PAUSED_LOCK = 1 << 0;
    uint constant PAUSED_UNLOCK = 1 << 1;

    constructor(
        bytes memory _nearTokenFactory, // TODO
        INearProver _prover, // TODO
        uint64 _minBlockAcceptanceHeight,
        address _admin,
        uint _pausedFlags
    ) AdminControlled(_admin, _pausedFlags) {}

    function lockToken(
        address ethToken,
        uint256 amount,
        string memory accountId
    ) public pausable(PAUSED_LOCK) {
        require(
            IERC20(ethToken).balanceOf(address(this)).add(amount) <=
                ((uint256(1) << 128) - 1),
            "Maximum tokens locked exceeded (< 2^128 - 1)"
        );
        IERC20(ethToken).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(address(ethToken), msg.sender, amount, accountId);
    }

    function unlockToken(
        bytes memory proofData,
        uint64 proofBlockHeight
    ) public pausable(PAUSED_UNLOCK) {
        // TODO: think about what proof updater contract should give
        require(msg.sender == allowedContract, "Access denied");
        ProofDecoder.ExecutionStatus memory status = _parseAndConsumeProof(
            proofData,
            proofBlockHeight
        );
        BurnResult memory result = _decodeBurnResult(status.successValue);
        IERC20(result.token).safeTransfer(result.recipient, result.amount);
        emit Unlocked(result.amount, result.recipient);
    }

    /// Parses the provided proof and consumes it if it's not already used.
    /// The consumed event cannot be reused for future calls.
    function _parseAndConsumeProof(
        bytes memory proofData,
        uint64 proofBlockHeight
    ) internal returns (ProofDecoder.ExecutionStatus memory result) {
        require(
            prover.proveOutcome(proofData, proofBlockHeight),
            "Proof should be valid"
        );

        // Unpack the proof and extract the execution outcome.
        Borsh.Data memory borshData = Borsh.from(proofData);
        ProofDecoder.FullOutcomeProof memory fullOutcomeProof = borshData
            .decodeFullOutcomeProof();
        borshData.done();

        require(
            fullOutcomeProof.block_header_lite.inner_lite.height >=
                minBlockAcceptanceHeight,
            "Proof is from the ancient block"
        );

        bytes32 receiptId = fullOutcomeProof
            .outcome_proof
            .outcome_with_id
            .outcome
            .receipt_ids[0];
        require(
            !usedProofs[receiptId],
            "The burn event proof cannot be reused"
        );
        usedProofs[receiptId] = true;

        require(
            keccak256(
                fullOutcomeProof
                    .outcome_proof
                    .outcome_with_id
                    .outcome
                    .executor_id
            ) == keccak256(nearTokenFactory),
            "Can only unlock tokens from the linked proof producer on Near blockchain"
        );

        result = fullOutcomeProof.outcome_proof.outcome_with_id.outcome.status;
        require(
            !result.failed,
            "Cannot use failed execution outcome for unlocking the tokens"
        );
        require(
            !result.unknown,
            "Cannot use unknown execution outcome for unlocking the tokens"
        );
    }

    // tokenFallback implements the ContractReceiver interface from ERC223-token-standard.
    // This allows to support ERC223 tokens with no extra cost.
    // The function always passes: we don't need to make any decision and the contract always
    // accept token transfers transfer.
    function tokenFallback(
        address _from,
        uint _value,
        bytes memory _data
    ) public pure {}

    function adminTransfer(
        IERC20 token,
        address destination,
        uint amount
    ) public onlyAdmin {
        token.safeTransfer(destination, amount);
    }
}
