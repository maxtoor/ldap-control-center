#!/usr/bin/env python3
import argparse
import os
from typing import Dict, List, Set, Tuple

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPAttributeError, LDAPObjectClassError


def as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def connect(host: str, port: int, use_ssl: bool, bind_dn: str, password: str) -> Connection:
    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
    return Connection(server, user=bind_dn, password=password, auto_bind=True)


def ensure_ou(conn: Connection, base_dn: str, label: str) -> None:
    exists = conn.search(
        search_base=base_dn,
        search_filter="(objectClass=organizationalUnit)",
        attributes=["ou"],
        search_scope="BASE",
    )
    if exists:
        return

    first_rdn = base_dn.split(",", 1)[0]
    if not first_rdn.lower().startswith("ou="):
        raise ValueError(f"{label} non valido: {base_dn}")
    ou_value = first_rdn.split("=", 1)[1]

    conn.add(
        dn=base_dn,
        object_class=["top", "organizationalUnit"],
        attributes={"ou": ou_value},
    )
    if conn.result["description"] != "success":
        raise RuntimeError(f"Errore creazione OU target {label}: {conn.result}")


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


def load_legacy_users(conn: Connection, base_dn: str) -> List[Dict]:
    user_attributes = ["uid", "cn", "sn", "mail", "givenName", "userPassword", "sAMAccountName"]
    try:
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=inetOrgPerson)",
            attributes=user_attributes,
        )
    except LDAPAttributeError:
        # Some LDAP servers reject unknown attributes in the query list.
        fallback_attributes = [a for a in user_attributes if a != "sAMAccountName"]
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=inetOrgPerson)",
            attributes=fallback_attributes,
        )
    users: List[Dict] = []
    for entry in conn.entries:
        data = entry.entry_attributes_as_dict
        uid_values = data.get("uid", [])
        if not uid_values:
            continue
        users.append(
            {
                "uid": str(uid_values[0]),
                "cn": str((data.get("cn") or [uid_values[0]])[0]),
                "sn": str((data.get("sn") or [uid_values[0]])[0]),
                "givenName": str((data.get("givenName") or [""])[0]),
                "mail": str((data.get("mail") or [""])[0]),
                "userPassword": (data.get("userPassword") or [None])[0],
                "sAMAccountName": str((data.get("sAMAccountName") or [""])[0]),
            }
        )
    return users


def load_legacy_groups(conn: Connection, base_dn: str, groups_filter: str) -> List[Dict]:
    group_attributes = [
        "cn",
        "description",
        "member",
        "uniqueMember",
        "memberUid",
        "objectClass",
        "gidNumber",
    ]
    try:
        conn.search(
            search_base=base_dn,
            search_filter=groups_filter,
            attributes=group_attributes,
        )
    except LDAPObjectClassError:
        # Some LDAP schemas reject unsupported objectClass values in filters (e.g. objectClass=group).
        fallback_filters = [
            "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
            "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
            "(objectClass=posixGroup)",
        ]
        matched = False
        for fallback_filter in fallback_filters:
            try:
                conn.search(
                    search_base=base_dn,
                    search_filter=fallback_filter,
                    attributes=group_attributes,
                )
                matched = True
                break
            except LDAPObjectClassError:
                continue
        if not matched:
            raise
    except LDAPAttributeError:
        # Some LDAP servers reject unknown attributes in the query list.
        fallback_attributes = [a for a in group_attributes if a not in {"memberUid", "gidNumber"}]
        conn.search(
            search_base=base_dn,
            search_filter=groups_filter,
            attributes=fallback_attributes,
        )
    groups: List[Dict] = []
    for entry in conn.entries:
        data = entry.entry_attributes_as_dict
        cn_values = data.get("cn", [])
        if not cn_values:
            continue

        raw_members: List[str] = []
        for attr in ("member", "uniqueMember", "memberUid"):
            for value in data.get(attr, []):
                if isinstance(value, bytes):
                    raw_members.append(value.decode("utf-8", errors="ignore"))
                else:
                    raw_members.append(str(value))

        groups.append(
            {
                "cn": str(cn_values[0]),
                "description": str((data.get("description") or [""])[0]),
                "raw_members": raw_members,
                "objectClass": [str(v) for v in data.get("objectClass", [])],
            }
        )
    return groups


def entry_exists(conn: Connection, dn: str) -> bool:
    return conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        attributes=["1.1"],
        search_scope="BASE",
    )


def create_user(conn: Connection, users_base_dn: str, user: Dict, dry_run: bool) -> str:
    user_dn = f"uid={user['uid']},{users_base_dn}"

    if entry_exists(conn, user_dn):
        return "skipped_exists"

    attributes = {
        "uid": user["uid"],
        "cn": user["cn"],
        "sn": user["sn"],
        "givenName": user["givenName"] or derive_given_name(user["cn"], user["sn"]),
        "mail": user["mail"],
    }

    if user["userPassword"] is not None:
        # Copy userPassword as-is to preserve existing hash format where possible.
        attributes["userPassword"] = user["userPassword"]

    if dry_run:
        return "dry_run"

    target_object_classes_raw = os.getenv(
        "LDAP_DEFAULT_OBJECT_CLASSES",
        "inetOrgPerson,organizationalPerson,person,top",
    )
    target_object_classes = [c.strip() for c in target_object_classes_raw.split(",") if c.strip()]

    conn.add(dn=user_dn, object_class=target_object_classes, attributes=attributes)
    if conn.result["description"] != "success":
        raise RuntimeError(f"Errore creazione utente {user['uid']}: {conn.result}")
    return "created"


def load_target_uids(conn: Connection, users_base_dn: str) -> Set[str]:
    conn.search(
        search_base=users_base_dn,
        search_filter="(objectClass=inetOrgPerson)",
        attributes=["uid"],
    )
    uids: Set[str] = set()
    for entry in conn.entries:
        uid = str(entry.uid.value or "")
        if uid:
            uids.add(uid)
    return uids


def uid_from_member(member: str) -> str:
    candidate = member.strip()
    if not candidate:
        return ""

    if "=" not in candidate:
        return candidate

    for part in candidate.split(","):
        rdn = part.strip()
        if "=" not in rdn:
            continue
        key, value = rdn.split("=", 1)
        if key.strip().lower() == "uid" and value.strip():
            return value.strip()
    return ""


def build_legacy_identifier_map(users: List[Dict]) -> Dict[Tuple[str, str], str]:
    id_map: Dict[Tuple[str, str], str] = {}
    for user in users:
        uid = user["uid"]
        pairs = [
            ("uid", user.get("uid", "")),
            ("cn", user.get("cn", "")),
            ("samaccountname", user.get("sAMAccountName", "")),
        ]
        for key, value in pairs:
            value = str(value or "").strip().lower()
            if value:
                id_map[(key, value)] = uid
    return id_map


def member_identifier(member: str) -> Tuple[str, str]:
    candidate = member.strip()
    if not candidate:
        return ("", "")

    if "=" not in candidate:
        return ("uid", candidate)

    first_rdn = candidate.split(",", 1)[0]
    if "=" not in first_rdn:
        return ("", "")
    key, value = first_rdn.split("=", 1)
    return (key.strip().lower(), value.strip())


def normalize_member_dns(
    raw_members: List[str],
    target_users_base_dn: str,
    existing_uids: Set[str],
    legacy_id_map: Dict[Tuple[str, str], str],
) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for raw in raw_members:
        key, value = member_identifier(raw)
        uid = ""

        if key in {"uid", "cn", "samaccountname"}:
            uid = legacy_id_map.get((key, value.lower()), "")
        elif key == "":
            uid = ""
        else:
            # fallback: try parsing uid from any RDN in DN
            uid = uid_from_member(raw)
            if not uid:
                uid = legacy_id_map.get(("cn", value.lower()), "")

        if not uid:
            continue
        if uid not in existing_uids:
            continue
        member_dn = f"uid={uid},{target_users_base_dn}"
        if member_dn in seen:
            continue
        seen.add(member_dn)
        normalized.append(member_dn)
    return normalized


def create_group(
    conn: Connection,
    target_groups_base_dn: str,
    target_users_base_dn: str,
    group: Dict,
    existing_uids: Set[str],
    legacy_id_map: Dict[Tuple[str, str], str],
    dry_run: bool,
) -> str:
    group_dn = f"cn={group['cn']},{target_groups_base_dn}"

    if entry_exists(conn, group_dn):
        return "skipped_exists"

    member_dns = normalize_member_dns(group["raw_members"], target_users_base_dn, existing_uids, legacy_id_map)
    if not member_dns:
        return "skipped_no_members"

    if dry_run:
        return "dry_run"

    attributes = {
        "cn": group["cn"],
        "member": member_dns,
    }
    if group["description"]:
        attributes["description"] = group["description"]

    conn.add(
        dn=group_dn,
        object_class=["top", "groupOfNames"],
        attributes=attributes,
    )
    if conn.result["description"] != "success":
        raise RuntimeError(f"Errore creazione gruppo {group['cn']}: {conn.result}")
    return "created"


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrazione utenti da LDAP legacy a nuovo OpenLDAP")
    parser.add_argument("--dry-run", action="store_true", help="Mostra cosa verrebbe importato senza scrivere")
    parser.add_argument("--include-groups", action="store_true", help="Importa anche i gruppi legacy")
    parser.add_argument(
        "--groups-filter",
        default="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group))",
        help="Filtro LDAP per selezionare gruppi legacy",
    )
    parser.add_argument(
        "--debug-groups",
        action="store_true",
        help="Stampa dettagli diagnostici dei gruppi trovati nel legacy LDAP",
    )
    args = parser.parse_args()

    legacy_host = os.getenv("LEGACY_LDAP_HOST")
    legacy_port = int(os.getenv("LEGACY_LDAP_PORT", "389"))
    legacy_use_ssl = as_bool(os.getenv("LEGACY_LDAP_USE_SSL", "false"))
    legacy_bind_dn = os.getenv("LEGACY_LDAP_BIND_DN")
    legacy_bind_password = os.getenv("LEGACY_LDAP_BIND_PASSWORD")
    legacy_users_base_dn = os.getenv("LEGACY_LDAP_USERS_BASE_DN")
    legacy_groups_base_dn = os.getenv("LEGACY_LDAP_GROUPS_BASE_DN")

    target_host = os.getenv("LDAP_HOST", "openldap")
    target_port = int(os.getenv("LDAP_PORT", "389"))
    target_use_ssl = as_bool(os.getenv("LDAP_USE_SSL", "false"))
    target_bind_dn = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org")
    target_bind_password = os.getenv("LDAP_ADMIN_PASSWORD", "admin")
    target_users_base_dn = os.getenv("LDAP_USERS_BASE_DN", "ou=users,dc=example,dc=org")
    target_groups_base_dn = os.getenv("LDAP_GROUPS_BASE_DN", "ou=groups,dc=example,dc=org")

    required = {
        "LEGACY_LDAP_HOST": legacy_host,
        "LEGACY_LDAP_BIND_DN": legacy_bind_dn,
        "LEGACY_LDAP_BIND_PASSWORD": legacy_bind_password,
        "LEGACY_LDAP_USERS_BASE_DN": legacy_users_base_dn,
    }
    if args.include_groups:
        required["LEGACY_LDAP_GROUPS_BASE_DN"] = legacy_groups_base_dn

    missing = [k for k, v in required.items() if not v]
    if missing:
        raise ValueError(f"Variabili mancanti: {', '.join(missing)}")

    legacy_conn = connect(
        host=legacy_host,
        port=legacy_port,
        use_ssl=legacy_use_ssl,
        bind_dn=legacy_bind_dn,
        password=legacy_bind_password,
    )
    target_conn = connect(
        host=target_host,
        port=target_port,
        use_ssl=target_use_ssl,
        bind_dn=target_bind_dn,
        password=target_bind_password,
    )

    try:
        ensure_ou(target_conn, target_users_base_dn, "LDAP_USERS_BASE_DN")
        users = load_legacy_users(legacy_conn, legacy_users_base_dn)

        created = 0
        skipped = 0
        dry = 0

        for user in users:
            result = create_user(target_conn, target_users_base_dn, user, args.dry_run)
            if result == "created":
                created += 1
            elif result == "skipped_exists":
                skipped += 1
            elif result == "dry_run":
                dry += 1
            print(f"[user:{result}] {user['uid']}")

        print("---")
        print(f"Utenti legacy: {len(users)}")
        print(f"Utenti creati: {created}")
        print(f"Utenti gia presenti: {skipped}")
        if args.dry_run:
            print(f"Utenti simulati: {dry}")

        if args.include_groups:
            ensure_ou(target_conn, target_groups_base_dn, "LDAP_GROUPS_BASE_DN")
            groups = load_legacy_groups(legacy_conn, legacy_groups_base_dn, args.groups_filter)
            existing_uids = load_target_uids(target_conn, target_users_base_dn)
            legacy_id_map = build_legacy_identifier_map(users)

            groups_created = 0
            groups_skipped_exists = 0
            groups_skipped_no_members = 0
            groups_dry = 0

            if not groups:
                print(
                    f"[group:warning] Nessun gruppo trovato in base '{legacy_groups_base_dn}' con filtro '{args.groups_filter}'"
                )

            for group in groups:
                if args.debug_groups:
                    print(
                        f"[group:debug] cn={group['cn']} objectClass={group['objectClass']} raw_members={len(group['raw_members'])}"
                    )
                result = create_group(
                    target_conn,
                    target_groups_base_dn,
                    target_users_base_dn,
                    group,
                    existing_uids,
                    legacy_id_map,
                    args.dry_run,
                )
                if result == "created":
                    groups_created += 1
                elif result == "skipped_exists":
                    groups_skipped_exists += 1
                elif result == "skipped_no_members":
                    groups_skipped_no_members += 1
                elif result == "dry_run":
                    groups_dry += 1
                print(f"[group:{result}] {group['cn']}")

            print("---")
            print(f"Gruppi legacy: {len(groups)}")
            print(f"Gruppi creati: {groups_created}")
            print(f"Gruppi gia presenti: {groups_skipped_exists}")
            print(f"Gruppi saltati (nessun membro valido): {groups_skipped_no_members}")
            if args.dry_run:
                print(f"Gruppi simulati: {groups_dry}")
    finally:
        legacy_conn.unbind()
        target_conn.unbind()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
