// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AdaptiveTrust
/// @notice Trust layer for the adaptive IoT security framework.
///         Validates edge encryption decisions against on-chain policy,
///         anchors integrity digests, enforces access control and records
///         an audit trail of access and tamper events.
/// @dev    Only fixed-size types are used (no strings) to keep gas low.
contract AdaptiveTrust {
    // ---- Encodings -------------------------------------------------------
    // Security class: 0 = Low, 1 = Medium, 2 = High
    // Encryption mode: 0 = None, 1 = ASCON-AEAD128, 2 = AES-GCM + Masking,
    //                  3 = AES-256-GCM, 4 = AES-GCM + Paillier PHE
    // Role:            1 = Doctor, 2 = Nurse, 3 = Admin, 4 = Analyst, 5 = Operator

    address public owner;
    uint32 public policyVersion;

    struct Device {
        bytes32 dataType;   // bound at registration; edge cannot relabel it
        bool active;
    }

    struct Record {
        bytes32 integrityHash; // SHA-256(ciphertext || metadata || ref)
        bytes32 refDigest;     // SHA-256(storage reference: IPFS CID or DB key)
        bytes32 devId;
        // packed slot
        uint64 ts;
        uint32 policyVer;
        uint8 class_;
        uint8 mode;
        bool exists;
        uint8 status;      // 0 = ok, 1 = flagged non-conformant (fits in the same slot)
    }

    mapping(address => bool) public edgeNodes;        // gateways allowed to log
    mapping(address => uint8) public userRole;        // 0 = unregistered
    mapping(bytes32 => Device) public devices;
    mapping(bytes32 => uint8) public minClass;        // dataType => minimum class
    mapping(uint8 => uint8) public allowedModes;      // class => bitmask of modes
    mapping(uint8 => mapping(bytes32 => bool)) public roleCanRead;   // role => dataType
    mapping(address => mapping(bytes32 => bool)) public explicitGrant; // user => dataId
    mapping(bytes32 => Record) public records;
    // Key-release-service (KRS) nodes and their non-conformance votes
    mapping(address => bool) public krsNodes;
    uint8 public krsThreshold;
    mapping(bytes32 => uint8) public ncVotes;
    mapping(bytes32 => mapping(address => bool)) public ncVoted;

    event PolicyUpdated(uint32 version);
    event PolicyValidated(bytes32 indexed dataId, uint8 class_, uint8 mode);
    event PolicyRejected(bytes32 indexed dataId, uint8 class_, uint8 mode, uint8 reason);
    event DecisionLogged(bytes32 indexed dataId, bytes32 indexed devId, bytes32 integrityHash, bytes32 refDigest);
    event AccessGranted(bytes32 indexed dataId, address indexed user, uint256 requestId);
    event AccessDenied(bytes32 indexed dataId, address indexed user, uint8 reason);
    event TamperDetected(bytes32 indexed dataId, address indexed reporter, bytes32 observedHash);
    event NonConformanceReported(bytes32 indexed dataId, address indexed reporter, uint8 reason);
    event NonConformanceVote(bytes32 indexed dataId, address indexed krsNode, uint8 reason);
    event RecordFlagged(bytes32 indexed dataId, uint8 reason);

    // Rejection reasons
    uint8 constant R_UNKNOWN_DEVICE = 1;
    uint8 constant R_CLASS_DOWNGRADE = 2;
    uint8 constant R_MODE_NOT_ALLOWED = 3;
    uint8 constant R_DUPLICATE = 4;
    uint8 constant R_NOT_REGISTERED = 5;
    uint8 constant R_NO_PERMISSION = 6;
    uint8 constant R_NO_RECORD = 7;
    uint8 constant R_NONCONFORMANT = 8;

    uint256 private requestCounter;

    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    modifier onlyEdge() { require(edgeNodes[msg.sender], "edge"); _; }

    constructor() { owner = msg.sender; policyVersion = 1; }

    // ---- Administration ---------------------------------------------------
    function setEdgeNode(address node, bool ok) external onlyOwner { edgeNodes[node] = ok; }
    function registerUser(address user, uint8 role) external onlyOwner { userRole[user] = role; }
    function registerDevice(bytes32 devId, bytes32 dataType) external onlyOwner {
        devices[devId] = Device(dataType, true);
    }
    function setMinClass(bytes32 dataType, uint8 c) external onlyOwner { minClass[dataType] = c; _bump(); }
    function setAllowedModes(uint8 c, uint8 mask) external onlyOwner { allowedModes[c] = mask; _bump(); }
    function setRoleCanRead(uint8 role, bytes32 dataType, bool ok) external onlyOwner { roleCanRead[role][dataType] = ok; }
    function grant(address user, bytes32 dataId, bool ok) external onlyOwner { explicitGrant[user][dataId] = ok; }
    function setKrsNode(address node, bool ok) external onlyOwner { krsNodes[node] = ok; }
    function setKrsThreshold(uint8 t) external onlyOwner { krsThreshold = t; }

    // ---- Conformance -------------------------------------------------------
    /// @notice Any registered user who finds that a record's committed key does not open the
    ///         anchored envelope under the declared mode reports it (evidence goes to the KRS nodes).
    function reportNonConformance(bytes32 dataId, uint8 reason) external {
        require(userRole[msg.sender] != 0 || edgeNodes[msg.sender], "reporter");
        require(records[dataId].exists, "record");
        emit NonConformanceReported(dataId, msg.sender, reason);
    }

    /// @notice A KRS node that has independently verified the evidence votes; at krsThreshold
    ///         distinct votes the record is flagged and further access requests are denied.
    function voteNonConformance(bytes32 dataId, uint8 reason) external {
        require(krsNodes[msg.sender], "krs");
        Record storage r = records[dataId];
        require(r.exists, "record");
        if (ncVoted[dataId][msg.sender] || r.status != 0) return;
        ncVoted[dataId][msg.sender] = true;
        ncVotes[dataId] += 1;
        emit NonConformanceVote(dataId, msg.sender, reason);
        if (ncVotes[dataId] >= krsThreshold) {
            r.status = 1;
            emit RecordFlagged(dataId, reason);
        }
    }
    function _bump() internal { policyVersion += 1; emit PolicyUpdated(policyVersion); }

    // ---- Write path: validate + anchor in one transaction -----------------
    /// @return accepted true if the decision complied with policy and was anchored
    function logDecision(
        bytes32 dataId,
        bytes32 devId,
        uint8 class_,
        uint8 mode,
        bytes32 integrityHash,
        bytes32 refDigest
    ) external onlyEdge returns (bool accepted) {
        Device storage d = devices[devId];
        if (!d.active) { emit PolicyRejected(dataId, class_, mode, R_UNKNOWN_DEVICE); return false; }
        if (records[dataId].exists) { emit PolicyRejected(dataId, class_, mode, R_DUPLICATE); return false; }
        // Class claimed by the edge may not be below the floor bound to the device's data type.
        if (class_ < minClass[d.dataType]) { emit PolicyRejected(dataId, class_, mode, R_CLASS_DOWNGRADE); return false; }
        if ((allowedModes[class_] >> mode) & 1 == 0) { emit PolicyRejected(dataId, class_, mode, R_MODE_NOT_ALLOWED); return false; }

        records[dataId] = Record({
            integrityHash: integrityHash,
            refDigest: refDigest,
            devId: devId,
            ts: uint64(block.timestamp),
            policyVer: policyVersion,
            class_: class_,
            mode: mode,
            exists: true,
            status: 0
        });
        emit PolicyValidated(dataId, class_, mode);
        emit DecisionLogged(dataId, devId, integrityHash, refDigest);
        return true;
    }

    // ---- Read path ---------------------------------------------------------
    function isAuthorized(address user, bytes32 dataId) public view returns (bool) {
        uint8 role = userRole[user];
        if (role == 0) return false;
        Record storage r = records[dataId];
        if (!r.exists) return false;
        return explicitGrant[user][dataId] || roleCanRead[role][devices[r.devId].dataType];
    }

    /// @notice State-changing access request: the emitted AccessGranted event (with requestId)
    ///         is the precondition the key-release service checks before releasing a key.
    function requestAccess(bytes32 dataId) external returns (bool) {
        if (userRole[msg.sender] == 0) { emit AccessDenied(dataId, msg.sender, R_NOT_REGISTERED); return false; }
        if (!records[dataId].exists) { emit AccessDenied(dataId, msg.sender, R_NO_RECORD); return false; }
        if (records[dataId].status != 0) { emit AccessDenied(dataId, msg.sender, R_NONCONFORMANT); return false; }
        if (!isAuthorized(msg.sender, dataId)) { emit AccessDenied(dataId, msg.sender, R_NO_PERMISSION); return false; }
        requestCounter += 1;
        emit AccessGranted(dataId, msg.sender, requestCounter);
        return true;
    }

    function reportTamper(bytes32 dataId, bytes32 observedHash) external {
        require(userRole[msg.sender] != 0 || edgeNodes[msg.sender], "reporter");
        require(records[dataId].exists, "record");
        emit TamperDetected(dataId, msg.sender, observedHash);
    }

    function getRecord(bytes32 dataId) external view returns (
        bytes32 integrityHash, bytes32 refDigest, bytes32 devId,
        uint64 ts, uint32 policyVer, uint8 class_, uint8 mode, bool exists, uint8 status
    ) {
        Record storage r = records[dataId];
        return (r.integrityHash, r.refDigest, r.devId, r.ts, r.policyVer, r.class_, r.mode, r.exists, r.status);
    }
}
