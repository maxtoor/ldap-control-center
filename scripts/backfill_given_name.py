#!/usr/bin/env python3
import argparse
import os
from typing import List, Tuple

from ldap3 import ALL, MODIFY_REPLACE, Connection, Server


def as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def connect() -> Connection:
    host = os.getenv("LDAP_HOST", "openldap")
    port = int(os.getenv("LDAP_PORT", "389"))
    use_ssl = as_bool(os.getenv("LDAP_USE_SSL", "false"))
    bind_dn = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org")
    bind_password = os.getenv("LDAP_ADMIN_PASSWORD", "admin")

    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
    return Connection(server, user=bind_dn, password=bind_password, auto_bind=True)


def derive_given_name(cn: str, sn: str) -> str:
    cn_clean = (cn or "").strip()
    sn_clean = (sn or "").strip()
    if not cn_clean:
        return ""

    if sn_clean and cn_clean.lower().endswith(sn_clean.lower()):
        base = cn_clean[: len(cn_clean) - len(sn_clean)].strip()
        if base:
            return base

    parts = [p for p in cn_clean.split() if p]
    if len(parts) > 1:
        return " ".join(parts[:-1]).strip()
    return cn_clean


def load_candidates(conn: Connection, users_base_dn: str) -> List[Tuple[str, str, str, str]]:
    conn.search(
        search_base=users_base_dn,
        search_filter="(objectClass=inetOrgPerson)",
        attributes=["uid", "cn", "sn", "givenName", "displayName"],
    )

    candidates = []
    for entry in conn.entries:
        uid = str(entry.uid.value or "").strip()
        cn = str(entry.cn.value or "").strip()
        sn = str(entry.sn.value or "").strip()
        given_name = str(entry.givenName.value or "").strip()
        if not uid or not cn:
            continue
        if given_name:
            continue
        derived = derive_given_name(cn=cn, sn=sn)
        if not derived:
            continue
        candidates.append((uid, cn, sn, derived))
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill givenName da cn/sn per utenti importati")
    parser.add_argument("--dry-run", action="store_true", help="Mostra modifiche senza scrivere")
    args = parser.parse_args()

    users_base_dn = os.getenv("LDAP_USERS_BASE_DN", "ou=users,dc=example,dc=org")

    conn = connect()
    try:
        candidates = load_candidates(conn, users_base_dn)

        updated = 0
        simulated = 0
        failed = 0

        for uid, cn, _sn, given_name in candidates:
            user_dn = f"uid={uid},{users_base_dn}"
            if args.dry_run:
                simulated += 1
                print(f"[dry_run] {uid}: givenName='{given_name}', displayName='{cn}'")
                continue

            changes = {
                "givenName": [(MODIFY_REPLACE, [given_name])],
                "displayName": [(MODIFY_REPLACE, [cn])],
            }
            conn.modify(user_dn, changes)
            if conn.result["description"] == "success":
                updated += 1
                print(f"[updated] {uid}: givenName='{given_name}', displayName='{cn}'")
            else:
                failed += 1
                print(f"[failed] {uid}: {conn.result}")

        print("---")
        print(f"Candidati: {len(candidates)}")
        print(f"Aggiornati: {updated}")
        print(f"Falliti: {failed}")
        if args.dry_run:
            print(f"Simulati: {simulated}")
    finally:
        conn.unbind()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
