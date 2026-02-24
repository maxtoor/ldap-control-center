# LDAP Control Center

Versione corrente: `0.1.0`  
Licenza: `GNU GPLv3` (vedi file `LICENSE`)
Autore: `Emilio Paolo Castelluccio`

Applicazione di gestione utenti basata su OpenLDAP con:
- OpenLDAP come directory target
- phpLDAPadmin per amministrazione avanzata
- Web app FastAPI per operazioni utente comuni (crea/lista/update password/delete)
- Gestione gruppi LDAP (`groupOfNames`) da UI
- Script di migrazione utenti (e opzionalmente gruppi) da LDAP legacy

## Nota di trasparenza

Parti del codice sono state sviluppate con supporto Codex.

## Avvio rapido

1. Copia configurazione ambiente:

```bash
cp .env.example .env
```

Opzionale (branding header app in `.env`):
- `APP_TITLE` titolo applicazione
- `APP_LOGO_URL` URL/logo path (es. `https://.../logo.png`)
- `APP_LOGO_LINK` link cliccabile sul logo (es. `https://www.cnr.it` o `/users`)

Accesso applicazione (`/login`):
- `APP_ADMIN_USERNAME` utente admin web app
- `APP_ADMIN_PASSWORD` password admin web app
- `APP_SESSION_SECRET` segreto firma cookie sessione
- `APP_SESSION_TTL_HOURS` durata sessione in ore

Invio email reset password:
- `SMTP_HOST`, `SMTP_PORT`
- `SMTP_USE_TLS` oppure `SMTP_USE_SSL` (non entrambi)
- `SMTP_USERNAME`, `SMTP_PASSWORD` (se richiesti dal provider)
- `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`
- `SMTP_RESET_SUBJECT`
- `PASSWORD_RESET_BASE_URL` (URL pubblico usato nel link email)
- `PASSWORD_RESET_TTL_MINUTES` validita token
- `PASSWORD_RESET_SHOW_LINK` (`true` solo per test locale, mostra link anche a schermo)

2. Avvia stack:

```bash
docker compose up --build -d
```

3. Accedi ai servizi:
- Login app: `http://localhost:8000/login`
- App utenti (lista): `http://localhost:8000/users`
- App utenti (creazione): `http://localhost:8000/users/new`
- App gruppi (lista): `http://localhost:8000/groups`
- App gruppi (creazione): `http://localhost:8000/groups/new`
- App utility import legacy: `http://localhost:8000/utilities`
- phpLDAPadmin: `http://localhost:8081`

Credenziali LDAP default:
- Bind DN: `cn=admin,dc=example,dc=org`
- Password: `admin`

Credenziali web app default:
- Username: `admin`
- Password: `admin`

## Aggiornamento stack

Aggiornamento automatico completo (check versioni + backup + update + smoke test + rollback su errore):

```bash
./scripts/autoupdate_stack.py
```

Opzioni utili:

```bash
./scripts/autoupdate_stack.py --dry-run
./scripts/autoupdate_stack.py --skip-backup
```

I backup LDIF vengono salvati in `backups/update-YYYYMMDD-HHMMSS/`.

Aggiornamento guidato senza check versioni (manuale tag già aggiornati):

```bash
./scripts/update_stack.sh
```

### Avviso nuove versioni immagini

Controllo manuale:

```bash
docker compose exec app python scripts/check_image_updates.py
```

Con notifica email (se ci sono update disponibili):

```bash
docker compose exec app python scripts/check_image_updates.py --email-to tuo.nome@icb.cnr.it
```

Oppure imposta in `.env`:
- `UPDATE_NOTIFY_EMAIL=tuo.nome@icb.cnr.it`

e usa:

```bash
docker compose exec app python scripts/check_image_updates.py
```

Esempio cron giornaliero (08:00):

```bash
0 8 * * * cd /Users/master/Documents/projects/gestan && docker compose exec -T app python scripts/check_image_updates.py >> /Users/master/Documents/projects/gestan/backups/update-check.log 2>&1
```

## Migrazione da vecchio LDAP

Configura in `.env` i parametri `LEGACY_*`.

Puoi eseguire l'import anche da interfaccia web:
- Menu `Utility` -> `Utility import LDAP legacy`
- Opzioni supportate: `--dry-run`, `--include-groups`, `--debug-groups`, `--groups-filter`
- L'output del comando viene mostrato direttamente nella pagina

### Import utenti (dry-run)

```bash
docker compose exec app python scripts/import_from_legacy.py --dry-run
```

### Import utenti (reale)

```bash
docker compose exec app python scripts/import_from_legacy.py
```

### Import utenti + gruppi (dry-run)

```bash
docker compose exec app python scripts/import_from_legacy.py --dry-run --include-groups --groups-filter '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))'
```

### Import utenti + gruppi (reale)

```bash
docker compose exec app python scripts/import_from_legacy.py --include-groups --groups-filter '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))'
```

### Diagnostica gruppi (debug)

```bash
docker compose exec app python scripts/import_from_legacy.py --dry-run --include-groups --debug-groups --groups-filter '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))'
```

### Backfill givenName per utenti importati

```bash
docker compose exec app python scripts/backfill_given_name.py --dry-run
```

```bash
docker compose exec app python scripts/backfill_given_name.py
```

## Note su password/hash

Lo script copia `userPassword` dal legacy LDAP al nuovo LDAP senza trasformazioni.
Questo consente, se il formato hash e la policy sono compatibili, di mantenere la validità delle password esistenti.
In caso di incompatibilità hash/policy, prevedi un reset password post-migrazione.

## Note import gruppi

- I gruppi legacy supportati includono `groupOfNames`, `groupOfUniqueNames` e `posixGroup`.
- I membri vengono mappati per `uid` ai DN target: `uid=<uid>,<LDAP_USERS_BASE_DN>`.
- Un gruppo viene saltato se non ha almeno un membro valido nel target (vincolo schema `groupOfNames`).

## Self-service password reset

Gli utenti gestiscono la password in autonomia da:
- `http://localhost:8000/password/forgot`

Flusso:
1. Inserimento nome utente o email.
2. Generazione link di reset con token temporaneo.
3. Apertura link e impostazione nuova password.

Il link viene inviato via email all'indirizzo istituzionale LDAP dell'utente.
Se SMTP non e configurato o l'utente non ha una mail, il sistema risponde comunque in modo neutro e registra il dettaglio nei log.
