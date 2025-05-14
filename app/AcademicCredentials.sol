// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AcademicCredentials
 * @dev Smart contract for managing academic credentials in the Erasmus program
 */
contract AcademicCredentials {
    // Status of credentials
    enum CredentialStatus { Active, Revoked }
    
    // Structure for a credential
    struct Credential {
        string uuid;
        address issuer;
        bytes32 studentHash; // Hash of student ID for privacy
        bytes32 credentialHash; // Hash of credential data
        uint256 issueTimestamp;
        CredentialStatus status;
        bool exists;
    }
    
    // Structure for revocation
    struct RevocationRecord {
        string credentialUuid;
        string reason;
        address revoker;
        uint256 timestamp;
        bool exists;
    }
    
    // Mapping from credential UUID to Credential
    mapping(string => Credential) private credentials;
    
    // Mapping from credential UUID to RevocationRecord
    mapping(string => RevocationRecord) private revocations;
    
    // List of credential UUIDs for iterating
    string[] private credentialUuids;
    
    // Events
    event CredentialIssued(string uuid, address indexed issuer, bytes32 indexed studentHash, uint256 timestamp);
    event CredentialRevoked(string uuid, address indexed revoker, string reason, uint256 timestamp);
    event CredentialVerified(string uuid, bool isValid, uint256 timestamp);
    
    // Modifiers
    modifier onlyIssuer(string memory _uuid) {
        require(credentials[_uuid].exists, "Credential does not exist");
        require(credentials[_uuid].issuer == msg.sender, "Only the issuer can perform this action");
        _;
    }
    
    modifier credentialExists(string memory _uuid) {
        require(credentials[_uuid].exists, "Credential does not exist");
        _;
    }
    
    /**
     * @dev Issues a new academic credential
     * @param _uuid Unique identifier for the credential
     * @param _studentHash Hash of the student ID (for privacy)
     * @param _credentialHash Hash of the credential data
     */
    function issueCredential(
        string memory _uuid,
        bytes32 _studentHash,
        bytes32 _credentialHash
    ) external {
        require(!credentials[_uuid].exists, "Credential already exists");
        
        Credential memory newCredential = Credential({
            uuid: _uuid,
            issuer: msg.sender,
            studentHash: _studentHash,
            credentialHash: _credentialHash,
            issueTimestamp: block.timestamp,
            status: CredentialStatus.Active,
            exists: true
        });
        
        credentials[_uuid] = newCredential;
        credentialUuids.push(_uuid);
        
        emit CredentialIssued(_uuid, msg.sender, _studentHash, block.timestamp);
    }
    
    /**
     * @dev Revokes an academic credential
     * @param _uuid UUID of the credential to revoke
     * @param _reason Reason for revocation
     */
    function revokeCredential(string memory _uuid, string memory _reason) 
        external 
        onlyIssuer(_uuid) 
    {
        require(credentials[_uuid].status == CredentialStatus.Active, "Credential is already revoked");
        
        // Update credential status
        credentials[_uuid].status = CredentialStatus.Revoked;
        
        // Create revocation record
        RevocationRecord memory record = RevocationRecord({
            credentialUuid: _uuid,
            reason: _reason,
            revoker: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });
        
        revocations[_uuid] = record;
        
        emit CredentialRevoked(_uuid, msg.sender, _reason, block.timestamp);
    }
    
    /**
     * @dev Verifies a credential's validity
     * @param _uuid UUID of the credential to verify
     * @return status Status of the credential (Active/Revoked)
     * @return issuedAt Timestamp when the credential was issued
     */
    function verifyCredential(string memory _uuid) 
        external 
        credentialExists(_uuid)
        returns (uint8 status, uint256 issuedAt) 
    {
        Credential memory credential = credentials[_uuid];
        
        emit CredentialVerified(_uuid, credential.status == CredentialStatus.Active, block.timestamp);
        
        return (uint8(credential.status), credential.issueTimestamp);
    }
    
    /**
     * @dev Verifies if the provided credential hash matches the stored hash
     * @param _uuid UUID of the credential
     * @param _credentialHash Hash to verify against the stored hash
     * @return match Whether the hashes match
     */
    function verifyCredentialHash(string memory _uuid, bytes32 _credentialHash) 
        external 
        view 
        credentialExists(_uuid)
        returns (bool match) 
    {
        return credentials[_uuid].credentialHash == _credentialHash;
    }
    
    /**
     * @dev Gets the details of a revocation record
     * @param _uuid UUID of the credential
     * @return reason Reason for revocation
     * @return revoker Address of the revoker
     * @return timestamp Timestamp of revocation
     */
    function getRevocationDetails(string memory _uuid) 
        external 
        view 
        credentialExists(_uuid)
        returns (string memory reason, address revoker, uint256 timestamp) 
    {
        require(revocations[_uuid].exists, "No revocation record exists");
        RevocationRecord memory record = revocations[_uuid];
        return (record.reason, record.revoker, record.timestamp);
    }
    
    /**
     * @dev Gets the count of credentials in the system
     * @return count Number of credentials
     */
    function getCredentialCount() external view returns (uint256 count) {
        return credentialUuids.length;
    }
    
    /**
     * @dev Gets credential details by index
     * @param _index Index in the credentials array
     * @return uuid UUID of the credential
     * @return issuer Address of the issuer
     * @return status Status of the credential
     * @return issueTimestamp Timestamp when the credential was issued
     */
    function getCredentialByIndex(uint256 _index) 
        external 
        view 
        returns (string memory uuid, address issuer, uint8 status, uint256 issueTimestamp) 
    {
        require(_index < credentialUuids.length, "Index out of bounds");
        
        string memory uuid = credentialUuids[_index];
        Credential memory credential = credentials[uuid];
        
        return (
            credential.uuid,
            credential.issuer,
            uint8(credential.status),
            credential.issueTimestamp
        );
    }
}
