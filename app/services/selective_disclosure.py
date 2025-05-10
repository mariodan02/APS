# services/selective_disclosure.py
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from models import Credential

class SelectiveDisclosureService:
    """
    Servizio per la creazione e verifica di presentazioni con divulgazione selettiva.
    Utilizza tecniche di Zero-Knowledge per consentire la divulgazione di attributi selezionati
    senza rivelare l'intera credenziale.
    """
    
    @staticmethod
    def create_merkle_tree(credential_fields):
        """
        Crea un Merkle Tree dagli attributi della credenziale per consentire 
        la divulgazione selettiva.
        
        Args:
            credential_fields: Dizionario dei campi della credenziale
            
        Returns:
            dict: Struttura del Merkle Tree e radice
        """
        # Converti i campi in stringhe
        leaves = []
        field_map = {}
        
        # Genera le foglie dell'albero per ogni campo
        for key, value in credential_fields.items():
            if isinstance(value, dict):
                # Per campi nidificati, crea una foglia per ogni sottocampo
                for sub_key, sub_value in value.items():
                    field_name = f"{key}.{sub_key}"
                    leaf_content = json.dumps({field_name: sub_value})
                    leaf_hash = hashlib.sha256(leaf_content.encode()).hexdigest()
                    leaves.append(leaf_hash)
                    field_map[field_name] = {
                        "hash": leaf_hash,
                        "content": leaf_content,
                        "index": len(leaves) - 1
                    }
            else:
                # Per campi semplici
                leaf_content = json.dumps({key: value})
                leaf_hash = hashlib.sha256(leaf_content.encode()).hexdigest()
                leaves.append(leaf_hash)
                field_map[key] = {
                    "hash": leaf_hash,
                    "content": leaf_content,
                    "index": len(leaves) - 1
                }
        
        # Costruisci il Merkle Tree
        tree = MerkleTree(leaves)
        
        return {
            "root": tree.get_root(),
            "tree": tree,
            "field_map": field_map
        }
    
    @staticmethod
    def create_selective_disclosure(credential, disclosed_fields):
        """
        Crea una presentazione con divulgazione selettiva.
        
        Args:
            credential: Modello della credenziale
            disclosed_fields: Lista dei campi da divulgare
        
        Returns:
            dict: Presentazione selettiva
        """
        # Ottieni i dati completi della credenziale
        full_credential = credential.to_json(include_private=True)
        
        # Estrai i metadati essenziali
        presentation = {
            "metadati": {
                "versione": full_credential["metadati"]["versione"],
                "identificativoUUID": full_credential["metadati"]["identificativoUUID"],
                "firma": full_credential["metadati"]["firma"]
            },
            "attributiAccademici": {}
        }
        
        # Crea Merkle Tree per gli attributi accademici
        merkle_data = SelectiveDisclosureService.create_merkle_tree(
            full_credential["attributiAccademici"]
        )
        
        # Aggiungi la prova Merkle alla presentazione
        presentation["metadati"]["merkle_root"] = merkle_data["root"]
        
        # Aggiungi campi divulgati selettivamente
        for field in disclosed_fields:
            if field == "emittente":
                presentation["emittente"] = full_credential["emittente"]
            elif field.startswith("attributiAccademici."):
                # Gestisci campi nidificati
                parts = field.split(".")
                if len(parts) > 2:
                    main_field = parts[1]
                    sub_field = parts[2]
                    
                    # Inizializza il campo principale se non esiste
                    if main_field not in presentation["attributiAccademici"]:
                        presentation["attributiAccademici"][main_field] = {}
                    
                    # Aggiungi il sottocampo
                    if main_field in full_credential["attributiAccademici"]:
                        if sub_field in full_credential["attributiAccademici"][main_field]:
                            presentation["attributiAccademici"][main_field][sub_field] = \
                                full_credential["attributiAccademici"][main_field][sub_field]
                else:
                    # Campo diretto sotto attributiAccademici
                    main_field = parts[1]
                    if main_field in full_credential["attributiAccademici"]:
                        presentation["attributiAccademici"][main_field] = \
                            full_credential["attributiAccademici"][main_field]
        
        # Genera le prove per i campi divulgati
        proofs = {}
        for field in disclosed_fields:
            if field.startswith("attributiAccademici."):
                field_parts = field.split(".")
                if len(field_parts) > 1:
                    field_name = ".".join(field_parts[1:])
                    field_key = f"attributiAccademici.{field_name}"
                    
                    if field_key in merkle_data["field_map"]:
                        field_index = merkle_data["field_map"][field_key]["index"]
                        proof = merkle_data["tree"].get_proof(field_index)
                        proofs[field_key] = {
                            "proof": proof,
                            "index": field_index
                        }
        
        # Aggiungi le prove alla presentazione
        presentation["metadati"]["merkle_proofs"] = proofs
        
        return presentation
    
    @staticmethod
    def verify_selective_disclosure(presentation):
        """
        Verifica una presentazione con divulgazione selettiva.
        
        Args:
            presentation: Dizionario della presentazione selettiva
        
        Returns:
            bool: True se la presentazione è valida
        """
        # Verifica che siano presenti i metadati necessari
        if "metadati" not in presentation or \
           "identificativoUUID" not in presentation["metadati"] or \
           "merkle_root" not in presentation["metadati"] or \
           "merkle_proofs" not in presentation["metadati"]:
            return False
        
        # Verifica le prove Merkle per i campi divulgati
        merkle_root = presentation["metadati"]["merkle_root"]
        merkle_proofs = presentation["metadati"]["merkle_proofs"]
        
        # Verifica ogni campo divulgato
        for field_key, proof_data in merkle_proofs.items():
            # Estrai il valore del campo dalla presentazione
            field_parts = field_key.split(".")
            field_value = None
            
            if len(field_parts) > 2:
                # Campo nidificato (es. attributiAccademici.codiceCorso.codiceInterno)
                main_obj = presentation[field_parts[0]]
                if field_parts[1] in main_obj:
                    if len(field_parts) == 3 and field_parts[2] in main_obj[field_parts[1]]:
                        field_value = main_obj[field_parts[1]][field_parts[2]]
            else:
                # Campo diretto (es. attributiAccademici.creditiECTS)
                main_obj = presentation[field_parts[0]]
                if field_parts[1] in main_obj:
                    field_value = main_obj[field_parts[1]]
            
            if field_value is None:
                return False
            
            # Ricalcola l'hash del campo
            leaf_content = json.dumps({".".join(field_parts[1:]): field_value})
            leaf_hash = hashlib.sha256(leaf_content.encode()).hexdigest()
            
            # Verifica la prova
            proof = proof_data["proof"]
            index = proof_data["index"]
            
            # Controlla se l'hash combina correttamente con la prova per ottenere la radice
            if not MerkleTree.verify_proof(merkle_root, leaf_hash, proof, index):
                return False
        
        return True


class MerkleTree:
    """
    Implementazione semplificata di un Merkle Tree per la divulgazione selettiva.
    """
    
    def __init__(self, leaves):
        """
        Costruisce un Merkle Tree dalle foglie.
        
        Args:
            leaves: Lista di hash delle foglie
        """
        self.leaves = leaves
        self.tree = [leaves]
        
        # Costruisci il tree
        self._build_tree()
    
    def _build_tree(self):
        """Costruisce i livelli del Merkle Tree dalle foglie alla radice"""
        current_level = self.leaves
        
        while len(current_level) > 1:
            next_level = []
            
            # Processa a coppie
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Hash di due elementi
                    combined = current_level[i] + current_level[i+1]
                    next_hash = hashlib.sha256(combined.encode()).hexdigest()
                else:
                    # Elemento dispari, hash con se stesso
                    combined = current_level[i] + current_level[i]
                    next_hash = hashlib.sha256(combined.encode()).hexdigest()
                
                next_level.append(next_hash)
            
            self.tree.append(next_level)
            current_level = next_level
    
    def get_root(self):
        """
        Ottieni la radice del Merkle Tree.
        
        Returns:
            str: Hash della radice
        """
        return self.tree[-1][0] if self.tree else None
    
    def get_proof(self, leaf_index):
        """
        Genera la prova Merkle per una foglia specifica.
        
        Args:
            leaf_index: Indice della foglia
        
        Returns:
            list: Lista di tuple (hash, posizione) che formano la prova
        """
        proof = []
        index = leaf_index
        
        for level in range(len(self.tree) - 1):
            level_length = len(self.tree[level])
            
            # Determina se l'hash complementare è a sinistra o a destra
            is_right = index % 2 == 0
            
            if is_right and index + 1 < level_length:
                # Il nodo corrente è a sinistra, prendi quello a destra
                proof.append((self.tree[level][index + 1], "right"))
            elif not is_right:
                # Il nodo corrente è a destra, prendi quello a sinistra
                proof.append((self.tree[level][index - 1], "left"))
            
            # Calcola l'indice per il livello successivo
            index = index // 2
        
        return proof
    
    @staticmethod
    def verify_proof(root, leaf_hash, proof, leaf_index):
        """
        Verifica una prova Merkle.
        
        Args:
            root: Hash della radice
            leaf_hash: Hash della foglia
            proof: Lista di tuple (hash, posizione)
            leaf_index: Indice della foglia
        
        Returns:
            bool: True se la prova è valida
        """
        current_hash = leaf_hash
        current_index = leaf_index
        
        for sibling_hash, position in proof:
            if position == "right":
                # Sibling a destra, concatena corrente + sibling
                combined = current_hash + sibling_hash
            else:
                # Sibling a sinistra, concatena sibling + corrente
                combined = sibling_hash + current_hash
            
            # Calcola il nuovo hash
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
            current_index = current_index // 2
        
        # Controlla se il risultato finale corrisponde alla radice
        return current_hash == root