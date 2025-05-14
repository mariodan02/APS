import json
import os
import hashlib
import logging
from datetime import datetime
from web3 import Web3
from web3.middleware import geth_poa_middleware
from solcx import compile_source, install_solc
from models import db, BlockchainBlock, Credential, RevocationRecord
from flask import current_app

class GanacheBlockchain:
    """
    Implements a blockchain interface using Ganache and the AcademicCredentials smart contract.
    This class manages the connection to the Ganache blockchain and provides methods for
    credential management operations.
    """
    
    def __init__(self, ganache_url='http://127.0.0.1:7545'):
        """
        Initializes the Ganache blockchain connection and loads the smart contract.
        
        Args:
            ganache_url: URL of the Ganache instance, defaults to http://127.0.0.1:7545
        """
        self.logger = logging.getLogger("GanacheBlockchain")
        self.logger.info(f"Initializing Ganache blockchain connection to {ganache_url}")
        
        # Connect to Ganache
        self.web3 = Web3(Web3.HTTPProvider(ganache_url))
        
        # Add POA middleware for compatibility with some Ethereum networks
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        # Check connection
        if not self.web3.is_connected():
            self.logger.error("Failed to connect to Ganache. Is it running?")
            raise ConnectionError("Could not connect to Ganache")
            
        self.logger.info(f"Connected to Ganache. Chain ID: {self.web3.eth.chain_id}")
        
        # Load contract if deployed, otherwise deploy it
        self.contract_address = self._get_contract_address()
        if not self.contract_address:
            self.contract_address = self._deploy_contract()
            
        self.contract = self._load_contract()
        self.logger.info(f"Contract loaded at address: {self.contract_address}")
        
        # TLS configuration
        self.use_tls = True  # For compatibility with existing code
        self.tls_manager = None
        
    def init_tls(self, cert_path=None, key_path=None, ca_path=None):
        """
        Initializes TLS for secure communication.
        Included for compatibility with the existing codebase.
        
        Args:
            cert_path: Path to certificate file
            key_path: Path to key file
            ca_path: Path to CA certificate file
            
        Returns:
            TLS manager instance
        """
        from tls import TLSManager
        
        if not self.tls_manager and self.use_tls:
            self.logger.info("Initializing TLS for blockchain communications")
            self.tls_manager = TLSManager(cert_path, key_path, ca_path)
        return self.tls_manager
        
    def _get_contract_address(self):
        """
        Retrieves the deployed contract address from a local file.
        
        Returns:
            Contract address if found, otherwise None
        """
        contract_file_path = os.path.join(os.path.dirname(__file__), 'contract_address.json')
        
        if os.path.exists(contract_file_path):
            try:
                with open(contract_file_path, 'r') as f:
                    data = json.load(f)
                    address = data.get('address')
                    if address and self.web3.is_address(address):
                        self.logger.info(f"Found deployed contract at {address}")
                        return address
            except Exception as e:
                self.logger.error(f"Error reading contract address file: {e}")
                
        return None
        
    def _deploy_contract(self):
        """
        Compiles and deploys the AcademicCredentials contract to the Ganache blockchain.
        
        Returns:
            Address of the deployed contract
        """
        self.logger.info("Deploying AcademicCredentials contract to Ganache")
        
        # Make sure solc is installed
        try:
            install_solc('0.8.0')
        except Exception as e:
            self.logger.warning(f"Could not install solc: {e}. Continuing assuming it's already installed.")
            
        # Load contract source
        contract_path = os.path.join(os.path.dirname(__file__), 'AcademicCredentials.sol')
        
        if not os.path.exists(contract_path):
            # Create the contract file if it doesn't exist
            from pathlib import Path
            Path(os.path.dirname(contract_path)).mkdir(parents=True, exist_ok=True)
            
            with open(contract_path, 'w') as f:
                f.write("""// SPDX-License-Identifier: MIT
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
}""")
        
        with open(contract_path, 'r') as f:
            contract_source_code = f.read()

        # Compile the contract
        compiled_sol = compile_source(
            contract_source_code,
            output_values=['abi', 'bin'],
            solc_version='0.8.0'
        )
        
        contract_id, contract_interface = compiled_sol.popitem()
        abi = contract_interface['abi']
        bytecode = contract_interface['bin']
        
        # Get an account to deploy from
        accounts = self.web3.eth.accounts
        if not accounts:
            self.logger.error("No accounts found in Ganache")
            raise ValueError("No accounts available for deployment")
            
        deployer_account = accounts[0]
        
        # Create the contract instance
        AcademicCredentials = self.web3.eth.contract(abi=abi, bytecode=bytecode)
        
        # Deploy the contract
        self.logger.info(f"Deploying from account: {deployer_account}")
        tx_hash = AcademicCredentials.constructor().transact({'from': deployer_account, 'gas': 2000000})
        
        # Wait for the transaction to be mined
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress
        
        # Save the contract address
        contract_file_path = os.path.join(os.path.dirname(__file__), 'contract_address.json')
        with open(contract_file_path, 'w') as f:
            json.dump({
                'address': contract_address,
                'abi': abi,
                'deployed_at': datetime.utcnow().isoformat()
            }, f)
            
        self.logger.info(f"Contract deployed at address: {contract_address}")
        return contract_address
        
    def _load_contract(self):
        """
        Loads the AcademicCredentials contract from its address.
        
        Returns:
            Contract instance
        """
        contract_file_path = os.path.join(os.path.dirname(__file__), 'contract_address.json')
        
        try:
            with open(contract_file_path, 'r') as f:
                data = json.load(f)
                abi = data.get('abi')
                
                if not abi:
                    raise ValueError("ABI not found in contract file")
                    
                return self.web3.eth.contract(address=self.contract_address, abi=abi)
                
        except Exception as e:
            self.logger.error(f"Error loading contract: {e}")
            raise
            
    def _get_transaction_account(self):
        """
        Gets a suitable account for sending transactions.
        
        Returns:
            Ethereum address to use for transactions
        """
        # In a real application, this would depend on the user's role and authentication
        # For simplicity, we'll use account[0] for issuing universities and account[1] for others
        accounts = self.web3.eth.accounts
        if len(accounts) < 2:
            return accounts[0]
            
        return accounts[0]  # Default to first account
        
    def _compute_credential_hash(self, credential):
        """
        Computes a hash of the credential data for on-chain storage.
        Only the hash is stored on-chain for privacy.
        
        Args:
            credential: Credential object
            
        Returns:
            Keccak256 hash of the credential data
        """
        # Create a dictionary with credential data
        cred_dict = {
            "uuid": credential.uuid,
            "issuer_id": credential.issuer_id,
            "student_id": credential.student_id,
            "course_code": credential.course_code,
            "course_isced_code": credential.course_isced_code,
            "exam_grade": credential.exam_grade,
            "exam_date": credential.exam_date.isoformat() if credential.exam_date else "",
            "ects_credits": credential.ects_credits,
            "issue_timestamp": credential.issue_timestamp.isoformat() if credential.issue_timestamp else ""
        }
        
        # Convert to JSON string and hash
        cred_json = json.dumps(cred_dict, sort_keys=True)
        return self.web3.keccak(text=cred_json)
        
    def _compute_student_hash(self, student_id):
        """
        Computes a hash of the student ID for privacy.
        
        Args:
            student_id: ID of the student
            
        Returns:
            Keccak256 hash of the student ID
        """
        return self.web3.keccak(text=str(student_id))
        
    def add_credential(self, credential):
        """
        Adds a credential to the blockchain.
        
        Args:
            credential: Credential object to add
            
        Returns:
            Transaction hash of the blockchain transaction
        """
        self.logger.info(f"Adding credential {credential.uuid} to blockchain")
        
        # Compute hashes
        credential_hash = self._compute_credential_hash(credential)
        student_hash = self._compute_student_hash(credential.student_id)
        
        # Get transaction account
        tx_account = self._get_transaction_account()
        
        # Issue the credential on the blockchain
        tx_hash = self.contract.functions.issueCredential(
            credential.uuid,
            student_hash,
            credential_hash
        ).transact({'from': tx_account, 'gas': 500000})
        
        # Wait for the transaction to be mined
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Create a BlockchainBlock record to maintain compatibility with the existing code
        block = self.web3.eth.get_block(tx_receipt.blockNumber)
        
        blockchain_block = BlockchainBlock(
            hash=self.web3.to_hex(tx_hash),
            previous_hash=self.web3.to_hex(block.parentHash),
            timestamp=datetime.fromtimestamp(block.timestamp),
            data=json.dumps({
                "type": "credential_issuance",
                "credential_uuid": credential.uuid,
                "issuer_id": credential.issuer_id,
                "student_id": credential.student_id,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "active",
                "block_number": block.number,
                "transaction_hash": self.web3.to_hex(tx_hash)
            }),
            nonce=block.nonce
        )
        
        db.session.add(blockchain_block)
        db.session.commit()
        
        self.logger.info(f"Credential {credential.uuid} added to blockchain, tx hash: {self.web3.to_hex(tx_hash)}")
        return self.web3.to_hex(tx_hash)
        
    def revoke_credential(self, credential_uuid, reason, revoker_id):
        """
        Revokes a credential on the blockchain.
        
        Args:
            credential_uuid: UUID of the credential to revoke
            reason: Reason for revocation
            revoker_id: ID of the user revoking the credential
            
        Returns:
            Transaction hash of the blockchain transaction
        """
        self.logger.info(f"Revoking credential {credential_uuid} on blockchain")
        
        # Get transaction account
        tx_account = self._get_transaction_account()
        
        # Revoke the credential on the blockchain
        tx_hash = self.contract.functions.revokeCredential(
            credential_uuid,
            reason
        ).transact({'from': tx_account, 'gas': 500000})
        
        # Wait for the transaction to be mined
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Create a BlockchainBlock record to maintain compatibility with the existing code
        block = self.web3.eth.get_block(tx_receipt.blockNumber)
        
        blockchain_block = BlockchainBlock(
            hash=self.web3.to_hex(tx_hash),
            previous_hash=self.web3.to_hex(block.parentHash),
            timestamp=datetime.fromtimestamp(block.timestamp),
            data=json.dumps({
                "type": "credential_revocation",
                "credential_uuid": credential_uuid,
                "reason": reason,
                "revoker_id": revoker_id,
                "timestamp": datetime.utcnow().isoformat(),
                "block_number": block.number,
                "transaction_hash": self.web3.to_hex(tx_hash)
            }),
            nonce=block.nonce
        )
        
        db.session.add(blockchain_block)
        db.session.commit()
        
        self.logger.info(f"Credential {credential_uuid} revoked on blockchain, tx hash: {self.web3.to_hex(tx_hash)}")
        return self.web3.to_hex(tx_hash)
        
    def verify_credential(self, credential_uuid):
        """
        Verifies the status of a credential on the blockchain.
        
        Args:
            credential_uuid: UUID of the credential to verify
            
        Returns:
            Status of the credential ("good", "revoked", or "unknown")
        """
        self.logger.info(f"Verifying credential {credential_uuid} on blockchain")
        
        try:
            # Call the contract to verify the credential
            status, _ = self.contract.functions.verifyCredential(credential_uuid).call()
            
            if status == 0:  # Active
                return "good"
            elif status == 1:  # Revoked
                return "revoked"
            else:
                return "unknown"
                
        except Exception as e:
            self.logger.error(f"Error verifying credential {credential_uuid}: {e}")
            return "unknown"
            
    def is_valid(self):
        """
        Checks if the blockchain is valid.
        This is included for compatibility with the existing codebase.
        
        Returns:
            True, as Ganache maintains a valid blockchain
        """
        # Ganache maintains a valid blockchain by design
        return True
        
    def verify_credential_hash(self, credential_uuid, credential):
        """
        Verifies if the credential data matches what's recorded on the blockchain.
        
        Args:
            credential_uuid: UUID of the credential
            credential: Credential object to verify
            
        Returns:
            Whether the credential hash matches
        """
        credential_hash = self._compute_credential_hash(credential)
        
        try:
            return self.contract.functions.verifyCredentialHash(
                credential_uuid, 
                credential_hash
            ).call()
            
        except Exception as e:
            self.logger.error(f"Error verifying credential hash: {e}")
            return False
            
    def get_revocation_details(self, credential_uuid):
        """
        Gets details about a revocation.
        
        Args:
            credential_uuid: UUID of the revoked credential
            
        Returns:
            Dictionary with revocation details or None if not revoked
        """
        try:
            reason, revoker, timestamp = self.contract.functions.getRevocationDetails(
                credential_uuid
            ).call()
            
            return {
                "reason": reason,
                "revoker": revoker,
                "timestamp": datetime.fromtimestamp(timestamp).isoformat()
            }
            
        except Exception as e:
            self.logger.debug(f"No revocation details for {credential_uuid}: {e}")
            return None
