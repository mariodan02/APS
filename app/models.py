#!/usr/bin/env python3
"""
Modelli per il sistema di credenziali accademiche
"""
import time
import json
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field

@dataclass
class MerkleTree:
    """Rappresenta un Merkle Tree per le credenziali"""
    root: str
    leaves: Dict[str, str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in dizionario"""
        return asdict(self)

@dataclass
class Credential:
    """Rappresenta una credenziale accademica"""
    credential_id: str
    student_id: str
    student_name: str
    issuer_id: str
    issuer_certificate_id: str
    merkle_root: str
    issue_timestamp: int = field(default_factory=lambda: int(time.time()))
    expiry_timestamp: int = field(default_factory=lambda: int(time.time()) + 31536000)  # +1 anno
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in dizionario"""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def to_json(self) -> str:
        """Converte l'oggetto in JSON"""
        return json.dumps(self.to_dict(), sort_keys=True)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Credential':
        """Crea un oggetto Credential da un dizionario"""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Credential':
        """Crea un oggetto Credential da JSON"""
        return cls.from_dict(json.loads(json_str))

@dataclass
class VerifiablePresentation:
    """Rappresenta una presentazione verificabile di credenziali"""
    presentation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    holder_id: str = None
    holder_name: str = None
    timestamp: int = field(default_factory=lambda: int(time.time()))
    disclosed_attributes: Dict[str, Any] = field(default_factory=dict)
    credential_id: str = None
    credential_metadata: Dict[str, Any] = field(default_factory=dict)
    merkle_proofs: Dict[str, str] = field(default_factory=dict)
    merkle_root: str = None
    holder_signature: Optional[str] = None
    holder_public_key: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in dizionario"""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def to_json(self) -> str:
        """Converte l'oggetto in JSON"""
        return json.dumps(self.to_dict(), sort_keys=True)
    
    def get_data_for_signing(self) -> Dict[str, Any]:
        """Restituisce i dati da firmare (senza firme e chiavi)"""
        data = self.to_dict()
        if "holder_signature" in data:
            del data["holder_signature"]
        if "holder_public_key" in data:
            del data["holder_public_key"]
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VerifiablePresentation':
        """Crea un oggetto VerifiablePresentation da un dizionario"""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'VerifiablePresentation':
        """Crea un oggetto VerifiablePresentation da JSON"""
        return cls.from_dict(json.loads(json_str))

@dataclass
class Student:
    """Rappresenta uno studente"""
    id: str
    name: str
    university_id: str
    registration_date: int = field(default_factory=lambda: int(time.time()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in dizionario"""
        return asdict(self)

@dataclass
class AcademicRecord:
    """Rappresenta un record accademico (esame)"""
    course_id: str
    course_name: str
    credits: int
    grade: int
    date: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in dizionario"""
        return asdict(self)