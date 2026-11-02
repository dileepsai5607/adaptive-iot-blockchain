// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BareAnchor
/// @notice Same-chain baseline: a registered writer anchors (dataId, digest, refDigest),
///         as in hash-anchoring designs, with no policy validation and no access control.
contract BareAnchor {
    address public owner;
    mapping(address => bool) public writers;
    struct Rec { bytes32 h; bytes32 ref; uint64 ts; }
    mapping(bytes32 => Rec) public recs;
    event Anchored(bytes32 indexed dataId, bytes32 h, bytes32 ref);
    constructor() { owner = msg.sender; }
    function setWriter(address w, bool ok) external { require(msg.sender == owner); writers[w] = ok; }
    function anchor(bytes32 dataId, bytes32 h, bytes32 ref) external {
        require(writers[msg.sender], "writer");
        require(recs[dataId].ts == 0, "dup");
        recs[dataId] = Rec(h, ref, uint64(block.timestamp));
        emit Anchored(dataId, h, ref);
    }
}
