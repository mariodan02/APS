#!/usr/bin/env python3
"""
Script per distribuire il contratto Solidity su Ganache
"""
import json
import os
import sys
from web3 import Web3
from web3.middleware import geth_poa_middleware

def deploy_contract(contract_json_path, ganache_url, private_key):
    """Distribuisce il contratto su Ganache"""
    # Connessione a Ganache
    web3 = Web3(Web3.HTTPProvider(ganache_url))
    web3.middleware_onion.inject(geth_poa_middleware, layer=0)
    
    if not web3.is_connected():
        print("Impossibile connettersi a Ganache. Assicurati che sia in esecuzione.")
        return None
    
    # Carica l'ABI e il bytecode del contratto
    with open(contract_json_path, 'r') as f:
        contract_data = json.load(f)
    
    abi = contract_data["abi"]
    bytecode = contract_data["bytecode"]
    
    # Account che distribuirà il contratto
    account = web3.eth.account.from_key(private_key)
    address = account.address
    
    print(f"Distribuzione del contratto dall'account: {address}")
    
    # Verifica il saldo dell'account
    balance = web3.eth.get_balance(address)
    balance_eth = web3.from_wei(balance, "ether")
    print(f"Saldo dell'account: {balance_eth} ETH")
    
    # Crea l'istanza del contratto
    contract_instance = web3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Stima del gas
    gas_estimate = contract_instance.constructor().estimate_gas({'from': address})
    
    # Prepara la transazione
    transaction = {
        'from': address,
        'gas': gas_estimate,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': web3.eth.get_transaction_count(address)
    }
    
    # Costruisce la transazione
    txn = contract_instance.constructor().build_transaction(transaction)
    
    # Firma la transazione
    signed_txn = account.sign_transaction(txn)
    
    # Invia la transazione
    txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f"Transazione inviata: {web3.to_hex(txn_hash)}")
    
    # Attendi la conferma
    txn_receipt = web3.eth.wait_for_transaction_receipt(txn_hash)
    
    contract_address = txn_receipt.contractAddress
    print(f"Contratto distribuito con successo all'indirizzo: {contract_address}")
    
    return contract_address

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Utilizzo: python deploy_contract.py <contract_json> <ganache_url> <private_key>")
        sys.exit(1)
    
    contract_json_path = sys.argv[1]
    ganache_url = sys.argv[2]
    private_key = sys.argv[3]
    
    deploy_contract(contract_json_path, ganache_url, private_key)