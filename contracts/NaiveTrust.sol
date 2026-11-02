// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NaiveTrust
/// @notice Baseline that follows the original draft's conceptual model:
///         string-typed class/mode/ref/role and two separate transactions
///         (validateDecision, then logHash). Used only for gas comparison.
contract NaiveTrust {
    address public owner;
    mapping(address => bool) public registeredUsers;
    mapping(address => string) public userRoles;
    mapping(bytes32 => bytes32) public dataHashes;
    mapping(bytes32 => string) public dataRefs;
    mapping(bytes32 => string) public dataClass;
    mapping(bytes32 => string) public dataMode;
    mapping(address => mapping(bytes32 => bool)) public permissions;
    mapping(bytes32 => string) public policy; // class => allowed mode

    event DecisionLogged(bytes32 dataId, string dataClass, string encMode);
    event PolicyValidated(bytes32 dataId);
    event PolicyRejected(bytes32 dataId);
    event HashLogged(bytes32 dataId, bytes32 hashValue, string ref);

    constructor() { owner = msg.sender; }

    function setPolicy(string memory c, string memory m) external { policy[keccak256(bytes(c))] = m; }
    function registerUser(address u, string memory role) external { registeredUsers[u] = true; userRoles[u] = role; }
    function grant(address u, bytes32 dataId) external { permissions[u][dataId] = true; }

    function validateDecision(bytes32 dataId, string memory c, string memory m) public returns (bool) {
        if (keccak256(bytes(policy[keccak256(bytes(c))])) == keccak256(bytes(m))) {
            dataClass[dataId] = c;
            dataMode[dataId] = m;
            emit PolicyValidated(dataId);
            emit DecisionLogged(dataId, c, m);
            return true;
        }
        emit PolicyRejected(dataId);
        return false;
    }

    function logHash(bytes32 dataId, bytes32 hashValue, string memory ref) public returns (bool) {
        dataHashes[dataId] = hashValue;
        dataRefs[dataId] = ref;
        emit HashLogged(dataId, hashValue, ref);
        return true;
    }

    function authorizeAccess(address u, bytes32 dataId) public view returns (bool) {
        return registeredUsers[u] && permissions[u][dataId];
    }
}
