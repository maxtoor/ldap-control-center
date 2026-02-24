# Changelog

Tutte le modifiche rilevanti a questo progetto saranno documentate in questo file.

## [0.1.0] - 2026-02-24

### Added
- Setup iniziale stack Docker con OpenLDAP, phpLDAPadmin e app FastAPI.
- Gestione utenti LDAP da UI (creazione, modifica, eliminazione, reset password).
- Gestione gruppi LDAP (`groupOfNames`) da UI.
- Utility import da LDAP legacy (utenti e gruppi), con modalita dry-run.
- Script operativi per controllo update immagini e aggiornamento stack con backup/rollback.
