# Blockchain Ledger

Registro locale append-only per file binari. Ogni blocco lega il proprio contenuto
al precedente tramite SHA-256. Richiede Python 3.10 o successivo e usa la
libreria standard, incluso SQLite. I checkpoint Ed25519 richiedono OpenSSL 3.

## Uso

```sh
printf 'primo documento\n' > documento.txt
python3 ledger.py --db registro.db append documento.txt
python3 ledger.py --db registro.db verify
```

L'operazione `append` accetta più file e salva un blocco per file, fino a 1 MiB
ciascuno. Il lotto viene applicato in una sola transazione. L'output include
l'hash finale (`tip`). Salvalo in uno spazio fidato separato e passalo come
`--tip HASH` a `verify` per verificare lo stato esatto a cui corrisponde.
`verify` restituisce codice 1 per gli errori di integrità e di accesso.

## Test e benchmark

```sh
python3 -m unittest discover -s tests -v
python3 benchmark.py --blocks 10000 --bytes 256
```

Il benchmark misura una singola scrittura in lotto e la scansione immediatamente
successiva, su un database temporaneo su disco. La verifica può beneficiare
della cache del sistema operativo. Il lettore controlla un blocco alla volta,
con memoria Python limitata dalla dimensione massima del payload. La verifica
ha costo lineare nel numero di blocchi e nei byte memorizzati.

## Formato e modello di fiducia

Il digest copre il prefisso ASCII `blockchain-ledger:v1` seguito da un byte zero,
l'altezza e il timestamp Unix in nanosecondi come interi unsigned a 64 bit
big-endian, i 32 byte dell'hash precedente e il payload. Il primo blocco ha
altezza zero e usa 32 byte zero come hash precedente.

Questo progetto implementa un registro locale a singolo database. Il contenuto
è memorizzato in chiaro. Chi può riscrivere il database può ricalcolare l'intera
catena. Un checkpoint conservato separatamente consente di rilevare anche
la riscrittura completa e il troncamento dello stato attestato. Il progetto
opera senza rete peer-to-peer, consenso distribuito o criptovalute.

## Checkpoint autenticati

Genera una chiave HMAC-SHA-256 in un percorso protetto separato dal database.
Il comando crea il file con permessi `0600` sui sistemi POSIX e rifiuta di
sovrascrivere un file esistente. Usa una chiave distinta per ciascun registro.

```sh
python3 ledger.py keygen --key-file /percorso/protetto/registro.key
checkpoint=$(python3 ledger.py --db registro.db checkpoint --key-file /percorso/protetto/registro.key)
python3 ledger.py --db registro.db verify --checkpoint "$checkpoint" --key-file /percorso/protetto/registro.key
```

Il comando `checkpoint` verifica la catena e autentica un'istantanea non vuota.
Il token contiene il numero di blocchi, l'hash finale e un codice HMAC. La
verifica controlla il codice HMAC prima di leggere il database e richiede che
l'istantanea coincida esattamente con il token. Un nuovo lotto produce quindi
uno stato da attestare con un nuovo checkpoint.

L'attestazione richiede fiducia nello stato al momento della creazione del
checkpoint. Chi possiede la chiave può creare checkpoint validi e chi può
sostituire il token può riproporre un checkpoint precedente. Conserva quindi
l'ultimo checkpoint atteso in una posizione fidata e tieni la chiave fuori dal
repository e dal database. I payload restano memorizzati in chiaro.

## Verifica delle estensioni

Aggiungi `--allow-extension` a `verify` quando il checkpoint attesta un
prefisso fidato. Il comando verifica tutti i blocchi, confronta il prefisso
all'altezza attestata e accetta eventuali blocchi successivi. Conserva il
checkpoint più recente per applicare il limite minimo di avanzamento atteso.

## Impronte dei documenti

```sh
python3 ledger.py --db registro.db append --hash-only documento.pdf
python3 ledger.py --db registro.db verify --file documento.pdf
```

La modalità registra solo i 32 byte dell'impronta SHA-256, senza nome o
contenuto del file. Il calcolo legge il file a blocchi. Combina `--file` con
un checkpoint fidato per attestare l'appartenenza a uno stato specifico.
Con `--allow-extension`, la ricerca include anche i blocchi successivi al
prefisso autenticato. L'impronta può essere confrontata con documenti già
noti a chi accede al registro.

Al primo inserimento con `--hash-only`, SQLite aggiunge una colonna
`kind` nella stessa transazione. I blocchi precedenti conservano i loro hash.
Per i blocchi di tipo impronta si usa il prefisso ASCII
`blockchain-ledger:file-sha256:v1` seguito da un byte zero. Usa questa versione
del programma per aprire registri che contengono impronte.

## Checkpoint pubblici Ed25519

Questi comandi richiedono OpenSSL 3. Imposta `LEDGER_OPENSSL` al percorso del
binario se il comando `openssl` predefinito usa un'altra implementazione.

```sh
python3 ledger.py keygen --private-key registro.private.der
python3 ledger.py export-public --private-key registro.private.der --public-key registro.public.der
firmato=$(python3 ledger.py --db registro.db checkpoint --private-key registro.private.der)
python3 ledger.py --db registro.db verify --signed-checkpoint "$firmato" --public-key registro.public.der
```

Il token contiene numero di blocchi e hash finale, seguiti da una firma
Ed25519 di 64 byte. La firma copre il prefisso ASCII
`blockchain-ledger:ed25519:v1`, un byte zero e i 40 byte del corpo.
Distribuisci la chiave pubblica ai verificatori tramite un canale fidato.
La chiave privata DER è salvata senza cifratura con permessi `0600` su POSIX.

## Backup e ripristino verificati

```sh
python3 ledger.py --db registro.db backup copia.db --signed-checkpoint "$firmato" --public-key registro.public.der
python3 ledger.py --db ripristinato.db restore copia.db --signed-checkpoint "$firmato" --public-key registro.public.der
```

Entrambi i comandi accettano anche la coppia HMAC `--checkpoint` e
`--key-file`. Richiedono una corrispondenza esatta con il checkpoint.
SQLite crea un'istantanea coerente in un file temporaneo. Il comando
controlla l'integrità di SQLite e della catena prima di rendere disponibile
il file finale. La destinazione deve essere nuova e il suo filesystem deve
supportare i collegamenti fisici. Conserva backup e checkpoint in posizioni
distinte e protette. La copia include tutti i dati presenti nel database.
