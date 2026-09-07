// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceLocker
 * @dev Smart Contract for Tamper-Proof Digital Evidence Auditing & Chain of Custody
 * Compliant with Bharatiya Sakshya Adhiniyam (BSA 2023) / Section 65B Indian Evidence Act.
 */
contract EvidenceLocker {
    address public admin;

    struct EvidenceRecord {
        string caseNumber;
        string evidenceType;    // "CDR", "FIR", "UFED_EXTRACTION", "BANK_STMT", "ANPR"
        string fileHash;        // SHA-256 / IPFS CID
        string metadataHash;    // JSON metadata hash
        uint256 timestamp;
        address loggedBy;
        bool isVerified;
    }

    struct CustodyAction {
        string action;          // "INGESTED", "ANALYZED", "EXPORTED", "VERIFIED"
        string officerBadgeId;
        uint256 timestamp;
        string notes;
    }

    // Mapping: FileHash => EvidenceRecord
    mapping(string => EvidenceRecord) public evidenceRegistry;
    // Mapping: FileHash => Array of Custody Actions
    mapping(string => CustodyAction[]) public chainOfCustody;
    // Array of all registered evidence hashes
    string[] public allEvidenceHashes;

    event EvidenceLogged(
        string indexed caseNumber,
        string indexed fileHash,
        string evidenceType,
        uint256 timestamp,
        address indexed loggedBy
    );
    event CustodyUpdated(
        string indexed fileHash,
        string action,
        string officerBadgeId,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /**
     * @dev Register new forensic evidence with immutable cryptographic hash
     */
    function logEvidence(
        string memory _caseNumber,
        string memory _evidenceType,
        string memory _fileHash,
        string memory _metadataHash,
        string memory _officerBadgeId
    ) public {
        require(evidenceRegistry[_fileHash].timestamp == 0, "Evidence hash already registered");

        evidenceRegistry[_fileHash] = EvidenceRecord({
            caseNumber: _caseNumber,
            evidenceType: _evidenceType,
            fileHash: _fileHash,
            metadataHash: _metadataHash,
            timestamp: block.timestamp,
            loggedBy: msg.sender,
            isVerified: true
        });

        chainOfCustody[_fileHash].push(CustodyAction({
            action: "INITIAL_SEIZURE_AND_INGESTION",
            officerBadgeId: _officerBadgeId,
            timestamp: block.timestamp,
            notes: "Cryptographically registered under Section 63 BSA 2023"
        }));

        allEvidenceHashes.push(_fileHash);

        emit EvidenceLogged(_caseNumber, _fileHash, _evidenceType, block.timestamp, msg.sender);
    }

    /**
     * @dev Add an audit custody event to existing evidence
     */
    function appendCustodyAction(
        string memory _fileHash,
        string memory _action,
        string memory _officerBadgeId,
        string memory _notes
    ) public {
        require(evidenceRegistry[_fileHash].timestamp > 0, "Evidence not found");

        chainOfCustody[_fileHash].push(CustodyAction({
            action: _action,
            officerBadgeId: _officerBadgeId,
            timestamp: block.timestamp,
            notes: _notes
        }));

        emit CustodyUpdated(_fileHash, _action, _officerBadgeId, block.timestamp);
    }

    /**
     * @dev Verify if a file hash exists in the tamper-proof ledger
     */
    function verifyEvidence(string memory _fileHash) public view returns (bool, uint256, string memory) {
        EvidenceRecord memory record = evidenceRegistry[_fileHash];
        if (record.timestamp > 0) {
            return (true, record.timestamp, record.caseNumber);
        }
        return (false, 0, "");
    }
}
