#!/usr/bin/env python3
"""
Applicazione principale per il sistema di credenziali accademiche
"""
import os
import sys
import time
import json
import argparse
import hashlib
from typing import Dict, List, Any, Optional

# Importa i moduli del progetto
from crypto_utils import (
    generate_key_pair, hash_data, sign_data, verify_signature,
    encrypt_data, decrypt_data, generate_fernet_key
)
from blockchain import Blockchain
from models import Credential, VerifiablePresentation, Student, AcademicRecord
from ocsp_service import OCSPService
import x509_utils

class IssuerUniversity:
    """Università che emette credenziali accademiche"""
    
    def __init__(self, university_id: str, cert_file: str, key_file: str):
        self.id = university_id
        self.cert_file = cert_file
        self.key_file = key_file
        
        # Carica il certificato e la chiave
        self.cert_pem = x509_utils.load_certificate(cert_file)
        self.key_pem = x509_utils.load_private_key(key_file)
        
        # Database degli studenti (simulato)
        self.student_records = {}
        
        # Servizio OCSP per gestire lo stato delle credenziali
        self.ocsp_service = OCSPService("./instance/erasmus_credentials.db")
    
    def register_student(self, student_id: str, name: str) -> bool:
        """Registra uno studente nel database"""
        if student_id in self.student_records:
            return False
            
        self.student_records[student_id] = {
            "id": student_id,
            "name": name,
            "university_id": self.id,
            "registration_date": int(time.time()),
            "academic_records": {}
        }
        return True
    
    def add_academic_record(self, student_id: str, course_id: str, course_name: str, 
                           credits: int, grade: int) -> bool:
        """Aggiunge un record accademico (esame) a uno studente"""
        if student_id not in self.student_records:
            return False
            
        self.student_records[student_id]["academic_records"][course_id] = {
            "course_id": course_id,
            "course_name": course_name,
            "credits": credits,
            "grade": grade,
            "date": int(time.time())
        }
        return True
    
    def _create_merkle_tree(self, records: Dict[str, Any]) -> Dict[str, str]:
        """Crea un Merkle Tree dai dati degli esami"""
        leaves = {}
        
        # Crea nodi foglia (hash di ogni record)
        for course_id, record in records.items():
            record_data = f"{course_id}|{json.dumps(record, sort_keys=True)}"
            leaves[course_id] = hash_data(record_data)
        
        # Calcola la root (per semplicità, hash di tutti gli hash delle foglie)
        combined = "|".join(sorted([leaves[k] for k in leaves]))
        root = hash_data(combined)
        
        return {"root": root, "leaves": leaves}
    
    def issue_credential(self, student_id: str) -> Optional[Dict[str, Any]]:
        """Emette una credenziale accademica per uno studente"""
        if student_id not in self.student_records:
            return None
            
        student_data = self.student_records[student_id]
        
        # Crea il Merkle Tree dai dati accademici
        merkle_tree = self._create_merkle_tree(student_data["academic_records"])
        
        # Crea un ID univoco per la credenziale
        credential_id = hash_data(f"{self.id}:{student_id}:{time.time()}")
        
        # Crea l'oggetto credenziale
        credential = Credential(
            credential_id=credential_id,
            student_id=student_id,
            student_name=student_data["name"],
            issuer_id=self.id,
            issuer_certificate_id=self.id,  # Semplificato: usa ID università come ID certificato
            merkle_root=merkle_tree["root"]
        )
        
        # Firma la credenziale con la chiave privata dell'università
        data_to_sign = credential.to_json()
        signature = sign_data(data_to_sign, self.key_pem)
        credential.signature = signature
        
        # Registra la credenziale nel servizio OCSP
        self.ocsp_service.add_credential(credential_id, self.id)
        
        # Crea la credenziale completa
        complete_credential = {
            "credential": credential.to_dict(),
            "merkle_tree": merkle_tree,
            "academic_records": student_data["academic_records"]
        }
        
        return complete_credential
    
    def revoke_credential(self, credential_id: str, reason: str) -> bool:
        """Revoca una credenziale precedentemente emessa"""
        return self.ocsp_service.revoke_credential(credential_id, self.id, reason)

class Student:
    """Studente che detiene le credenziali accademiche"""
    
    def __init__(self, student_id: str, name: str):
        self.id = student_id
        self.name = name
        
        # Genera una coppia di chiavi per lo studente
        self.private_key_pem, self.public_key_pem = generate_key_pair()
        
        # Wallet delle credenziali
        self.wallet = {}
    
    def receive_credential(self, credential: Dict[str, Any]):
        """Riceve e archivia una credenziale"""
        credential_id = credential["credential"]["credential_id"]
        self.wallet[credential_id] = credential
        return credential_id
    
    def create_presentation(self, credential_id: str, attributes: List[str]) -> Optional[Dict[str, Any]]:
        """Crea una presentazione verificabile con attributi selettivi"""
        if credential_id not in self.wallet:
            return None
            
        credential = self.wallet[credential_id]
        merkle_tree = credential["merkle_tree"]
        academic_records = credential["academic_records"]
        
        # Filtra solo gli attributi richiesti
        disclosed_attributes = {}
        for attr in attributes:
            if attr in academic_records:
                disclosed_attributes[attr] = academic_records[attr]
        
        # Crea la presentazione
        presentation = VerifiablePresentation(
            holder_id=self.id,
            holder_name=self.name,
            credential_id=credential_id,
            credential_metadata=credential["credential"],
            disclosed_attributes=disclosed_attributes,
            merkle_proofs={attr: merkle_tree["leaves"][attr] for attr in attributes if attr in merkle_tree["leaves"]},
            merkle_root=merkle_tree["root"]
        )
        
        # Firma la presentazione
        data_to_sign = json.dumps(presentation.get_data_for_signing(), sort_keys=True)
        signature = sign_data(data_to_sign, self.private_key_pem)
        presentation.holder_signature = signature
        presentation.holder_public_key = self.public_key_pem.decode()
        
        return presentation.to_dict()
    
    def check_credential_status(self, credential_id: str, ocsp_service: OCSPService) -> Dict[str, Any]:
        """Verifica lo stato di una credenziale"""
        return ocsp_service.check_credential_status(credential_id)

class VerifierUniversity:
    """Università che verifica le credenziali accademiche"""
    
    def __init__(self, university_id: str, ca_cert_file: str):
        self.id = university_id
        
        # Carica il certificato CA per verificare i certificati delle altre università
        self.ca_cert_pem = x509_utils.load_certificate(ca_cert_file)
        
        # Servizio OCSP per verificare lo stato delle credenziali
        self.ocsp_service = OCSPService("./instance/erasmus_credentials.db")
    
    def verify_presentation(self, presentation: Dict[str, Any], issuer_cert_file: str) -> Dict[str, Any]:
        """Verifica una presentazione di credenziali"""
        try:
            # Carica il certificato dell'università emittente
            issuer_cert_pem = x509_utils.load_certificate(issuer_cert_file)
            
            # 1. Verifica la firma dello studente
            holder_public_key = presentation["holder_public_key"].encode()
            
            # Prepara i dati firmati (escludendo la firma stessa e la chiave pubblica)
            presentation_copy = presentation.copy()
            holder_signature = presentation_copy.pop("holder_signature")
            presentation_copy.pop("holder_public_key")
            
            data_to_verify = json.dumps(presentation_copy, sort_keys=True)
            
            if not verify_signature(data_to_verify, holder_signature, holder_public_key):
                return {"valid": False, "reason": "La firma dello studente non è valida"}
            
            # 2. Verifica lo stato della credenziale
            credential_id = presentation["credential_id"]
            credential_status = self.ocsp_service.check_credential_status(credential_id)
            
            if credential_status["status"] != "valid":
                return {"valid": False, "reason": f"La credenziale è stata revocata o non è valida: {credential_status['status']}"}
            
            # 3. Verifica la firma dell'università emittente
            credential_metadata = presentation["credential_metadata"]
            issuer_public_key = x509_utils.extract_public_key(issuer_cert_pem)
            
            # Prepara i dati firmati
            credential_copy = credential_metadata.copy()
            issuer_signature = credential_copy.pop("signature")
            
            data_to_verify = json.dumps(credential_copy, sort_keys=True)
            
            if not verify_signature(data_to_verify, issuer_signature, issuer_public_key):
                return {"valid": False, "reason": "La firma dell'università emittente non è valida"}
            
            # 4. Verifica la validità temporale
            current_time = int(time.time())
            if current_time > credential_copy["expiry_timestamp"]:
                return {"valid": False, "reason": "La credenziale è scaduta"}
            
            # 5. Verifica il Merkle Tree (versione semplificata)
            merkle_root = presentation["merkle_root"]
            if merkle_root != credential_copy["merkle_root"]:
                return {"valid": False, "reason": "La root del Merkle Tree non corrisponde alla credenziale"}
            
            # Tutte le verifiche sono passate
            return {
                "valid": True, 
                "holder_id": presentation["holder_id"],
                "holder_name": presentation["holder_name"],
                "issuer_id": credential_metadata["issuer_id"],
                "disclosed_attributes": presentation["disclosed_attributes"]
            }
            
        except Exception as e:
            return {"valid": False, "reason": f"Errore durante la verifica: {str(e)}"}

def setup_environment():
    """Inizializza l'ambiente di esecuzione"""
    # Crea le directory necessarie
    os.makedirs("./certificates", exist_ok=True)
    os.makedirs("./instance", exist_ok=True)
    
    # Verifica se i certificati esistono già
    if not os.path.exists("./certificates/ca_cert.pem"):
        print("Generazione dei certificati per la CA...")
        ca_cert, ca_key = x509_utils.generate_ca_certificate()
        
        # Salva i certificati
        x509_utils.save_certificate(ca_cert, "./certificates/ca_cert.pem")
        x509_utils.save_private_key(ca_key, "./certificates/ca_key.pem")
    
    # Genera certificati per le università se non esistono
    universities = [
        {"id": "università_di_salerno", "name": "Università di Salerno"},
        {"id": "université_de_rennes", "name": "Université de Rennes"}
    ]
    
    for univ in universities:
        cert_file = f"./certificates/{univ['id']}_cert.pem"
        key_file = f"./certificates/{univ['id']}_key.pem"
        
        if not os.path.exists(cert_file):
            print(f"Generazione dei certificati per {univ['name']}...")
            
            # Carica la CA
            ca_cert = x509_utils.load_certificate("./certificates/ca_cert.pem")
            ca_key = x509_utils.load_private_key("./certificates/ca_key.pem")
            
            # Genera il certificato
            univ_cert, univ_key = x509_utils.generate_university_certificate(
                ca_cert, ca_key, univ['name']
            )
            
            # Salva i certificati
            x509_utils.save_certificate(univ_cert, cert_file)
            x509_utils.save_private_key(univ_key, key_file)

def main():
    """Funzione principale dell'applicazione"""
    parser = argparse.ArgumentParser(description="Sistema di Credenziali Accademiche")
    
    subparsers = parser.add_subparsers(dest="command", help="Comandi disponibili")
    
    # Comando: setup
    setup_parser = subparsers.add_parser("setup", help="Inizializza l'ambiente")
    
    # Comando: issue
    issue_parser = subparsers.add_parser("issue", help="Emetti una credenziale")
    issue_parser.add_argument("--university", required=True, help="ID dell'università emittente")
    issue_parser.add_argument("--student", required=True, help="ID dello studente")
    issue_parser.add_argument("--output", required=True, help="File di output per la credenziale")
    
    # Comando: verify
    verify_parser = subparsers.add_parser("verify", help="Verifica una presentazione")
    verify_parser.add_argument("--university", required=True, help="ID dell'università verificatrice")
    verify_parser.add_argument("--presentation", required=True, help="File della presentazione da verificare")
    verify_parser.add_argument("--issuer", required=True, help="ID dell'università emittente")
    
    # Comando: revoke
    revoke_parser = subparsers.add_parser("revoke", help="Revoca una credenziale")
    revoke_parser.add_argument("--university", required=True, help="ID dell'università emittente")
    revoke_parser.add_argument("--credential", required=True, help="ID della credenziale da revocare")
    revoke_parser.add_argument("--reason", required=True, help="Motivo della revoca")
    
    # Comando: present
    present_parser = subparsers.add_parser("present", help="Crea una presentazione verificabile")
    present_parser.add_argument("--student", required=True, help="ID dello studente")
    present_parser.add_argument("--credential", required=True, help="File della credenziale")
    present_parser.add_argument("--attributes", required=True, help="Attributi da divulgare (separati da virgole)")
    present_parser.add_argument("--output", required=True, help="File di output per la presentazione")
    
    # Comando: demo
    demo_parser = subparsers.add_parser("demo", help="Esegui una dimostrazione completa")
    
    args = parser.parse_args()
    
    # Esegui il comando specificato
    if args.command == "setup":
        setup_environment()
        print("Ambiente inizializzato con successo!")
        
    elif args.command == "issue":
        # Carica l'università emittente
        univ = IssuerUniversity(
            args.university,
            f"./certificates/{args.university}_cert.pem",
            f"./certificates/{args.university}_key.pem"
        )
        
        # Registra lo studente (nella pratica, lo studente sarebbe già registrato)
        univ.register_student(args.student, "Nome Studente")
        
        # Aggiungi alcuni esami (nella pratica, gli esami sarebbero già nel database)
        univ.add_academic_record(args.student, "MAT101", "Matematica", 9, 28)
        univ.add_academic_record(args.student, "FIS102", "Fisica", 8, 30)
        univ.add_academic_record(args.student, "INF103", "Informatica", 10, 29)
        
        # Emetti la credenziale
        credential = univ.issue_credential(args.student)
        
        if credential:
            # Salva la credenziale su file
            with open(args.output, 'w') as f:
                json.dump(credential, f, indent=2)
            print(f"Credenziale emessa con successo! ID: {credential['credential']['credential_id']}")
        else:
            print("Errore nell'emissione della credenziale")
            
    elif args.command == "verify":
        # Carica l'università verificatrice
        verifier = VerifierUniversity(
            args.university,
            "./certificates/ca_cert.pem"
        )
        
        # Carica la presentazione
        with open(args.presentation, 'r') as f:
            presentation = json.load(f)
        
        # Verifica la presentazione
        result = verifier.verify_presentation(
            presentation,
            f"./certificates/{args.issuer}_cert.pem"
        )
        
        if result["valid"]:
            print("Presentazione verificata con successo!")
            print(f"Studente: {result['holder_name']} ({result['holder_id']})")
            print(f"Università emittente: {result['issuer_id']}")
            print("Attributi divulgati:")
            for key, value in result["disclosed_attributes"].items():
                print(f"  - {key}: {value}")
        else:
            print(f"Verifica fallita: {result['reason']}")
            
    elif args.command == "revoke":
        # Carica l'università emittente
        univ = IssuerUniversity(
            args.university,
            f"./certificates/{args.university}_cert.pem",
            f"./certificates/{args.university}_key.pem"
        )
        
        # Revoca la credenziale
        if univ.revoke_credential(args.credential, args.reason):
            print(f"Credenziale {args.credential} revocata con successo!")
        else:
            print("Errore nella revoca della credenziale")
            
    elif args.command == "present":
        # Carica la credenziale
        with open(args.credential, 'r') as f:
            credential = json.load(f)
        
        # Crea lo studente
        student = Student(args.student, "Nome Studente")
        
        # Ricevi la credenziale
        student.receive_credential(credential)
        credential_id = credential["credential"]["credential_id"]
        
        # Crea la presentazione
        attributes = args.attributes.split(',')
        presentation = student.create_presentation(credential_id, attributes)
        
        if presentation:
            # Salva la presentazione su file
            with open(args.output, 'w') as f:
                json.dump(presentation, f, indent=2)
            print(f"Presentazione creata con successo con {len(attributes)} attributi divulgati!")
        else:
            print("Errore nella creazione della presentazione")
            
    elif args.command == "demo":
        print("Esecuzione della dimostrazione...")
        
        # Inizializza l'ambiente
        setup_environment()
        
        # Crea le università
        univ_salerno = IssuerUniversity(
            "università_di_salerno",
            "./certificates/università_di_salerno_cert.pem",
            "./certificates/università_di_salerno_key.pem"
        )
        
        univ_rennes = VerifierUniversity(
            "université_de_rennes",
            "./certificates/ca_cert.pem"
        )
        
        # Crea uno studente
        student = Student("S12345", "Mario Rossi")
        
        print("\n1. Registrazione dello studente presso l'Università di Salerno")
        univ_salerno.register_student(student.id, student.name)
        
        print("\n2. Aggiunta di esami sostenuti dallo studente")
        univ_salerno.add_academic_record(student.id, "MAT101", "Matematica Avanzata", 9, 28)
        univ_salerno.add_academic_record(student.id, "FIS102", "Fisica Quantistica", 8, 30)
        univ_salerno.add_academic_record(student.id, "INF103", "Programmazione", 10, 29)
        univ_salerno.add_academic_record(student.id, "ING104", "Inglese B2", 5, 27)
        univ_salerno.add_academic_record(student.id, "ECO105", "Economia", 6, 26)
        
        print("\n3. Emissione della credenziale accademica")
        credential = univ_salerno.issue_credential(student.id)
        credential_id = credential["credential"]["credential_id"]
        print(f"   Credenziale emessa con ID: {credential_id}")
        
        print("\n4. Ricezione della credenziale da parte dello studente")
        student.receive_credential(credential)
        
        print("\n5. Creazione di una presentazione verificabile con divulgazione selettiva")
        print("   Lo studente sceglie di condividere solo i voti di Matematica e Fisica")
        presentation = student.create_presentation(credential_id, ["MAT101", "FIS102"])
        
        print("\n6. Verifica della presentazione da parte dell'Università di Rennes")
        result = univ_rennes.verify_presentation(
            presentation,
            "./certificates/università_di_salerno_cert.pem"
        )
        
        if result["valid"]:
            print("   Verifica completata con successo!")
            print(f"   Studente verificato: {result['holder_name']} ({result['holder_id']})")
            print("   Attributi divulgati:")
            for key, value in result["disclosed_attributes"].items():
                course_name = value["course_name"]
                grade = value["grade"]
                credits = value["credits"]
                print(f"   - {course_name}: {grade}/30 ({credits} CFU)")
        else:
            print(f"   Verifica fallita: {result['reason']}")
        
        print("\n7. Test di revoca")
        print("   L'Università di Salerno revoca la credenziale")
        univ_salerno.revoke_credential(credential_id, "Errore amministrativo")
        
        print("\n8. Verifica dopo la revoca")
        result = univ_rennes.verify_presentation(
            presentation,
            "./certificates/università_di_salerno_cert.pem"
        )
        
        if result["valid"]:
            print("   Verifica completata con successo (non dovrebbe accadere dopo la revoca)!")
        else:
            print(f"   Verifica fallita come previsto: {result['reason']}")
        
        print("\nDimostrazione completata con successo!")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()