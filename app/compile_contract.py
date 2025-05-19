#!/usr/bin/env python3
"""
Script per compilare il contratto Solidity e salvare l'ABI e il bytecode
"""
import json
import os
import sys
from solcx import compile_standard, install_solc

def compile_contract(solidity_file, output_dir):
    """Compila il contratto Solidity e salva l'ABI e il bytecode"""
    # Assicurati che la cartella di output esista
    os.makedirs(output_dir, exist_ok=True)
    
    # Installa solc se necessario
    install_solc("0.8.0")
    
    # Leggi il file Solidity
    with open(solidity_file, 'r') as f:
        contract_source = f.read()
    
    # Compila il contratto
    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {
                os.path.basename(solidity_file): {
                    "content": contract_source
                }
            },
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                    }
                }
            }
        },
        solc_version="0.8.0"
    )
    
    # Estrai il nome del contratto dal file
    contract_name = os.path.splitext(os.path.basename(solidity_file))[0]
    
    # Estrai l'ABI e il bytecode
    contract_data = compiled_sol["contracts"][os.path.basename(solidity_file)][contract_name]
    abi = contract_data["abi"]
    bytecode = contract_data["evm"]["bytecode"]["object"]
    
    # Salva l'ABI e il bytecode in un file JSON
    output_file = os.path.join(output_dir, f"{contract_name}.json")
    with open(output_file, 'w') as f:
        json.dump({"abi": abi, "bytecode": bytecode}, f, indent=2)
    
    print(f"Contratto compilato con successo. ABI e bytecode salvati in {output_file}")
    return output_file

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Utilizzo: python compile_contract.py <file_solidity> <dir_output>")
        sys.exit(1)
    
    solidity_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    compile_contract(solidity_file, output_dir)