// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AnchorACL
/// @notice Same-chain baseline: hash anchoring plus role-based access control with logged
///         access requests, but no validation of the protection decision.
contract AnchorACL {
    address public owner;
    mapping(address => bool) public writers;
    mapping(address => uint8) public userRole;
    mapping(uint8 => mapping(bytes32 => bool)) public roleCanRead;
    struct Rec { bytes32 h; bytes32 ref; bytes32 dataType; uint64 ts; }
    mapping(bytes32 => Rec) public recs;
    uint256 private counter;
    event Anchored(bytes32 indexed dataId, bytes32 h, bytes32 ref);
    event AccessGranted(bytes32 indexed dataId, address indexed user, uint256 requestId);
    event AccessDenied(bytes32 indexed dataId, address indexed user);
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setWriter(address w, bool ok) external onlyOwner { writers[w] = ok; }
    function registerUser(address u, uint8 role) external onlyOwner { userRole[u] = role; }
    function setRoleCanRead(uint8 role, bytes32 t, bool ok) external onlyOwner { roleCanRead[role][t] = ok; }
    function anchor(bytes32 dataId, bytes32 dataType, bytes32 h, bytes32 ref) external {
        require(writers[msg.sender], "writer");
        require(recs[dataId].ts == 0, "dup");
        recs[dataId] = Rec(h, ref, dataType, uint64(block.timestamp));
        emit Anchored(dataId, h, ref);
    }
    function requestAccess(bytes32 dataId) external returns (bool) {
        uint8 role = userRole[msg.sender];
        if (role == 0 || recs[dataId].ts == 0 || !roleCanRead[role][recs[dataId].dataType]) {
            emit AccessDenied(dataId, msg.sender); return false;
        }
        counter += 1;
        emit AccessGranted(dataId, msg.sender, counter);
        return true;
    }
}
