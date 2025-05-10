import hashlib
import json
import time
from datetime import datetime
from models import db, BlockchainBlock

class SimpleBlockchain:
    def __init__(self):
        # Check if blockchain exists, if not initialize it
        if BlockchainBlock.query.count() == 0:
            self.add_genesis_block()
    
    def add_genesis_block(self):
        """Create the genesis block for the blockchain"""
        genesis_block = BlockchainBlock(
            hash="0000genesis0000",
            previous_hash="0",
            timestamp=datetime.utcnow(),
            data=json.dumps({"message": "Genesis Block for Academic Credentials System"}),
            nonce=0
        )
        db.session.add(genesis_block)
        db.session.commit()
        return genesis_block
    
    def calculate_hash(self, index, previous_hash, timestamp, data, nonce):
        """Calculate hash for a block"""
        value = str(index) + str(previous_hash) + str(timestamp) + str(data) + str(nonce)
        return hashlib.sha256(value.encode('utf-8')).hexdigest()
    
    def get_last_block(self):
        """Get the last block in the blockchain"""
        return BlockchainBlock.query.order_by(BlockchainBlock.id.desc()).first()
    
    def proof_of_work(self, index, previous_hash, timestamp, data):
        """Simplified proof of work for block creation (only for simulation)"""
        nonce = 0
        computed_hash = self.calculate_hash(index, previous_hash, timestamp, data, nonce)
        
        # In a real blockchain, we'd look for a hash with specific characteristics
        # For this simulation, we just do a minimal work
        while not computed_hash.startswith('0'):
            nonce += 1
            computed_hash = self.calculate_hash(index, previous_hash, timestamp, data, nonce)
        
        return nonce, computed_hash
    
    def add_block(self, data):
        """Add a new block to the blockchain"""
        last_block = self.get_last_block()
        
        # Prepare new block data
        index = last_block.id + 1
        timestamp = datetime.utcnow()
        nonce, computed_hash = self.proof_of_work(index, last_block.hash, timestamp, data)
        
        # Create and save the new block
        new_block = BlockchainBlock(
            hash=computed_hash,
            previous_hash=last_block.hash,
            timestamp=timestamp,
            data=json.dumps(data),
            nonce=nonce
        )
        
        db.session.add(new_block)
        db.session.commit()
        return new_block
    
    def is_valid(self):
        """Validate the integrity of the blockchain"""
        blocks = BlockchainBlock.query.order_by(BlockchainBlock.id).all()
        
        for i in range(1, len(blocks)):
            current = blocks[i]
            previous = blocks[i-1]
            
            # Check if hash of current block is valid
            if current.previous_hash != previous.hash:
                return False
            
            # Check if hash is correctly calculated
            calculated_hash = self.calculate_hash(
                current.id, 
                current.previous_hash, 
                current.timestamp, 
                current.data, 
                current.nonce
            )
            
            if current.hash != calculated_hash:
                return False
        
        return True
    
    def add_credential(self, credential):
        """Add a credential to the blockchain"""
        data = {
            "type": "credential_issuance",
            "credential_uuid": credential.uuid,
            "issuer_id": credential.issuer_id,
            "student_id": credential.student_id,
            "timestamp": credential.issue_timestamp.isoformat(),
            "status": "active"
        }
        
        block = self.add_block(data)
        return block.hash
    
    def revoke_credential(self, credential_uuid, reason, revoker_id):
        """Add a revocation record to the blockchain"""
        data = {
            "type": "credential_revocation",
            "credential_uuid": credential_uuid,
            "reason": reason,
            "revoker_id": revoker_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        block = self.add_block(data)
        return block.hash
    
    def verify_credential(self, credential_uuid):
        """Check if a credential is valid or revoked"""
        blocks = BlockchainBlock.query.order_by(BlockchainBlock.id).all()
        
        issuance_block = None
        revocation_block = None
        
        for block in blocks:
            try:
                block_data = json.loads(block.data)
                
                if 'credential_uuid' in block_data and block_data['credential_uuid'] == credential_uuid:
                    if block_data['type'] == 'credential_issuance':
                        issuance_block = block
                    elif block_data['type'] == 'credential_revocation':
                        revocation_block = block
            except:
                continue
        
        if not issuance_block:
            return "unknown"  # Credential not found
        
        if revocation_block:
            return "revoked"  # Credential was revoked
            
        return "good"  # Credential is valid