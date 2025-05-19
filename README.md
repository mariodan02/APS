# Guida al Sistema di Credenziali Accademiche con Blockchain Ethereum

Questa guida spiega come utilizzare il sistema di credenziali accademiche modificato per lavorare con una blockchain Ethereum locale tramite Ganache.

## Prerequisiti

1. Installare le dipendenze:
```bash
pip install -r requirements.txt
```

2. Ganache in esecuzione su http://127.0.0.1:7545
   - Scaricare e installare [Ganache](https://trufflesuite.com/ganache/)
   - Avviare un nuovo workspace Ethereum

## Passi per l'utilizzo

### 1. Inizializzare l'ambiente

```bash
python app.py setup
```

Questo creerà le directory necessarie e i certificati per le università.

### 2. Compilare il contratto Solidity

```bash
python app.py compile
```

Questo compilerà il contratto Solidity e genererà il file ABI.

### 3. Distribuire il contratto sulla blockchain Ganache

```bash
python app.py deploy --private-key <CHIAVE_PRIVATA_ETH>
```

Dove `<CHIAVE_PRIVATA_ETH>` è la chiave privata di uno degli account su Ganache. Puoi ottenerla facendo clic su "Show Keys" nell'interfaccia di Ganache.

Questo comando restituirà l'indirizzo del contratto distribuito, che sarà necessario per i comandi successivi.

### 4. Emettere una credenziale

```bash
python app.py issue --university università_di_salerno --student S12345 --output credential.json --eth-private-key <CHIAVE_PRIVATA_ETH> --contract <INDIRIZZO_CONTRATTO>
```

Questo emetterà una credenziale per lo studente e la registrerà sulla blockchain.

### 5. Creare una presentazione verificabile

```bash
python app.py present --student S12345 --credential credential.json --attributes MAT101,FIS102 --output presentation.json
```

Questo creerà una presentazione verificabile che rivela solo gli attributi selezionati.

### 6. Verificare una presentazione

```bash
python app.py verify --university université_de_rennes --presentation presentation.json --issuer università_di_salerno --contract <INDIRIZZO_CONTRATTO>
```

Questo verificherà la presentazione, controllando la firma e lo stato della credenziale sulla blockchain.

### 7. Revocare una credenziale

```bash
python app.py revoke --university università_di_salerno --credential <ID_CREDENZIALE> --reason "Errore amministrativo" --eth-private-key <CHIAVE_PRIVATA_ETH> --contract <INDIRIZZO_CONTRATTO>
```

Questo revocherà la credenziale sulla blockchain.

### 8. Verificare lo stato di una credenziale

```bash
python app.py check --credential <ID_CREDENZIALE> --contract <INDIRIZZO_CONTRATTO>
```

Questo mostrerà lo stato attuale della credenziale sulla blockchain.

### 9. Eseguire una dimostrazione completa

```bash
python app.py demo --eth-private-key <CHIAVE_PRIVATA_ETH> --contract <INDIRIZZO_CONTRATTO>
```

Questo eseguirà una dimostrazione completa del sistema, emettendo una credenziale, creando una presentazione, verificandola, revocandola e dimostrando che la verifica fallisce dopo la revoca.

## Note importanti

1. **Chiavi private**: Le chiavi private Ethereum non dovrebbero mai essere condivise o hardcoded nel codice. In un ambiente di produzione, si dovrebbero utilizzare soluzioni più sicure come la gestione delle chiavi.

2. **Gas e costi di transazione**: Quando si utilizza una rete Ethereum reale (mainnet o testnet), ogni transazione ha un costo. Su Ganache, questo non è un problema, ma dovrebbe essere considerato in un ambiente di produzione.

3. **Web3 Provider**: Il sistema utilizza HTTP come provider Web3. In un ambiente di produzione, si consiglia di utilizzare provider più sicuri come WebSockets o IPC.

4. **Contratto Smart**: Il contratto Solidity fornito è un esempio semplice. In un ambiente di produzione, si dovrebbero considerare aspetti come l'aggiornabilità, la sicurezza e l'ottimizzazione dei costi del gas.