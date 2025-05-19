// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AcademicCredentials {
    struct Credential {
        string credentialId;
        string studentId;
        string issuerId;
        string status;
        string merkleRoot;
        string reason;
        uint256 timestamp;
        uint256 revocationTimestamp;
    }
    
    // Mapping dal credentialId alla Credential
    mapping(string => Credential) private credentials;
    
    // Evento emesso quando viene emessa una nuova credenziale
    event CredentialIssued(string credentialId, string studentId, string issuerId, uint256 timestamp);
    
    // Evento emesso quando una credenziale viene revocata
    event CredentialRevoked(string credentialId, string issuerId, string reason, uint256 timestamp);
    
    // Emette una nuova credenziale
    function issueCredential(
        string memory credentialId, 
        string memory studentId, 
        string memory issuerId,
        string memory merkleRoot
    ) public {
        require(bytes(credentials[credentialId].credentialId).length == 0, "Credential ID already exists");
        
        Credential storage cred = credentials[credentialId];
        cred.credentialId = credentialId;
        cred.studentId = studentId;
        cred.issuerId = issuerId;
        cred.merkleRoot = merkleRoot;
        cred.status = "valid";
        cred.timestamp = block.timestamp;
        
        emit CredentialIssued(credentialId, studentId, issuerId, block.timestamp);
    }
    
    // Revoca una credenziale esistente
    function revokeCredential(string memory credentialId, string memory issuerId, string memory reason) public {
        Credential storage cred = credentials[credentialId];
        
        // Verifica che la credenziale esista e appartenga all'emittente
        require(bytes(cred.credentialId).length > 0, "Credential does not exist");
        require(keccak256(bytes(cred.issuerId)) == keccak256(bytes(issuerId)), "Unauthorized issuer");
        
        cred.status = "revoked";
        cred.reason = reason;
        cred.revocationTimestamp = block.timestamp;
        
        emit CredentialRevoked(credentialId, issuerId, reason, block.timestamp);
    }
    
    // Ottiene lo stato di una credenziale
    function getCredentialStatus(string memory credentialId) public view returns (
        string memory id,
        string memory studentId,
        string memory issuer, 
        string memory status, 
        string memory merkleRoot,
        string memory reason, 
        uint256 timestamp, 
        uint256 revocationTimestamp
    ) {
        Credential memory cred = credentials[credentialId];
        
        return (
            cred.credentialId,
            cred.studentId,
            cred.issuerId,
            cred.status,
            cred.merkleRoot,
            cred.reason,
            cred.timestamp,
            cred.revocationTimestamp
        );
    }
}