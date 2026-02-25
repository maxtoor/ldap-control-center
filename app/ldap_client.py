import os
import json
from dataclasses import dataclass
from typing import List, Optional

from ldap3 import ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection, Server
from ldap3.utils.conv import escape_filter_chars


@dataclass
class LDAPUser:
    uid: str
    cn: str
    sn: str
    mail: str
    given_name: str
    display_name: str
    telephone_number: str
    mobile: str
    employee_number: str
    employee_type: str
    serial_number: str
    user_status: str
    employment_start: str
    employment_end: str
    personal_email: str
    office_name: str
    title: str
    notes: str
    dn: str


@dataclass
class LDAPGroup:
    cn: str
    description: str
    dn: str
    members: List[str]


class LDAPClient:
    _META_PREFIX = "LDAPCC_META:"

    def __init__(self) -> None:
        self.host = os.getenv("LDAP_HOST", "openldap")
        self.port = int(os.getenv("LDAP_PORT", "389"))
        self.use_ssl = os.getenv("LDAP_USE_SSL", "false").lower() == "true"
        self.admin_dn = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org")
        self.admin_password = os.getenv("LDAP_ADMIN_PASSWORD", "admin")
        self.users_base_dn = os.getenv("LDAP_USERS_BASE_DN", "ou=users,dc=example,dc=org")
        self.groups_base_dn = os.getenv("LDAP_GROUPS_BASE_DN", "ou=groups,dc=example,dc=org")
        object_classes = os.getenv(
            "LDAP_DEFAULT_OBJECT_CLASSES",
            "inetOrgPerson,organizationalPerson,person,top",
        )
        self.default_object_classes = [item.strip() for item in object_classes.split(",") if item.strip()]

    def _connect(self) -> Connection:
        server = Server(self.host, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
        conn = Connection(server, user=self.admin_dn, password=self.admin_password, auto_bind=True)
        return conn

    def _ensure_ou(self, ou_base_dn: str, label: str) -> None:
        conn = self._connect()
        try:
            if conn.search(
                search_base=ou_base_dn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=["ou"],
                search_scope="BASE",
            ):
                return

            first_rdn = ou_base_dn.split(",", 1)[0]
            if not first_rdn.lower().startswith("ou="):
                raise ValueError(f"{label} non valido: {ou_base_dn}")
            ou_value = first_rdn.split("=", 1)[1]

            conn.add(
                dn=ou_base_dn,
                object_class=["top", "organizationalUnit"],
                attributes={"ou": ou_value},
            )
            if not conn.result["description"] == "success":
                raise RuntimeError(f"Errore creazione OU {label}: {conn.result}")
        finally:
            conn.unbind()

    def ensure_users_ou(self) -> None:
        self._ensure_ou(self.users_base_dn, "LDAP_USERS_BASE_DN")

    def ensure_groups_ou(self) -> None:
        self._ensure_ou(self.groups_base_dn, "LDAP_GROUPS_BASE_DN")

    def _user_dn(self, uid: str) -> str:
        return f"uid={uid},{self.users_base_dn}"

    def _group_dn(self, cn: str) -> str:
        return f"cn={cn},{self.groups_base_dn}"

    def _uid_from_dn(self, user_dn: str) -> str:
        first_rdn = user_dn.split(",", 1)[0]
        if first_rdn.lower().startswith("uid="):
            return first_rdn.split("=", 1)[1]
        return user_dn

    def _group_members_from_entry(self, entry) -> List[str]:
        members: List[str] = []
        for value in list(entry.member.values) if hasattr(entry, "member") else []:
            members.append(self._uid_from_dn(str(value)))
        for value in list(entry.uniqueMember.values) if hasattr(entry, "uniqueMember") else []:
            members.append(self._uid_from_dn(str(value)))
        for value in list(entry.memberUid.values) if hasattr(entry, "memberUid") else []:
            members.append(str(value))
        # Preserva ordine e rimuove duplicati/vuoti.
        deduped: List[str] = []
        seen = set()
        for member in members:
            member_clean = member.strip()
            if not member_clean or member_clean in seen:
                continue
            seen.add(member_clean)
            deduped.append(member_clean)
        return deduped

    def _entry_exists(self, dn: str) -> bool:
        conn = self._connect()
        try:
            return conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                attributes=["1.1"],
                search_scope="BASE",
            )
        finally:
            conn.unbind()

    def _compose_cn(self, given_name: str, sn: str, fallback: str = "") -> str:
        cn = " ".join(part.strip() for part in [given_name, sn] if part and part.strip()).strip()
        return cn or fallback

    def _encode_description(
        self,
        notes: str,
        user_status: str,
        employment_start: str,
        employment_end: str,
        personal_email: str = "",
    ) -> str:
        metadata = {
            "user_status": user_status.strip(),
            "employment_start": employment_start.strip(),
            "employment_end": employment_end.strip(),
            "personal_email": personal_email.strip(),
        }
        payload = json.dumps(metadata, ensure_ascii=True, separators=(",", ":"))
        note_body = notes.strip()
        if note_body:
            return f"{self._META_PREFIX}{payload}\n{note_body}"
        return f"{self._META_PREFIX}{payload}"

    def _decode_description(self, raw_description: str) -> tuple[str, str, str, str, str]:
        text = (raw_description or "").strip()
        if not text.startswith(self._META_PREFIX):
            return text, "", "", "", ""

        meta_line, _, notes = text.partition("\n")
        payload = meta_line[len(self._META_PREFIX) :]
        try:
            metadata = json.loads(payload)
        except json.JSONDecodeError:
            return text, "", "", "", ""

        return (
            notes.strip(),
            str(metadata.get("user_status", "")),
            str(metadata.get("employment_start", "")),
            str(metadata.get("employment_end", "")),
            str(metadata.get("personal_email", "")),
        )

    def list_users(self) -> List[LDAPUser]:
        conn = self._connect()
        try:
            conn.search(
                search_base=self.users_base_dn,
                search_filter="(objectClass=inetOrgPerson)",
                attributes=[
                    "uid",
                    "cn",
                    "sn",
                    "mail",
                    "givenName",
                    "displayName",
                    "telephoneNumber",
                    "mobile",
                    "employeeNumber",
                    "employeeType",
                    "serialNumber",                    "physicalDeliveryOfficeName",
                    "title",
                    "description",
                ],
            )
            users: List[LDAPUser] = []
            for entry in conn.entries:
                notes, user_status, employment_start, employment_end, personal_email = self._decode_description(
                    str(entry.description.value or "")
                )
                users.append(
                    LDAPUser(
                        uid=str(entry.uid.value or ""),
                        cn=str(entry.cn.value or ""),
                        sn=str(entry.sn.value or ""),
                        mail=str(entry.mail.value or ""),
                        given_name=str(entry.givenName.value or ""),
                        display_name=str(entry.displayName.value or ""),
                        telephone_number=str(entry.telephoneNumber.value or ""),
                        mobile=str(entry.mobile.value or ""),
                        employee_number=str(entry.employeeNumber.value or ""),
                        employee_type=str(entry.employeeType.value or ""),
                        serial_number=str(entry.serialNumber.value or ""),
                        user_status=user_status,
                        employment_start=employment_start,
                        employment_end=employment_end,
                        personal_email=personal_email,
                        office_name=str(entry.physicalDeliveryOfficeName.value or ""),
                        title=str(entry.title.value or ""),
                        notes=notes,
                        dn=str(entry.entry_dn),
                    )
                )
            users.sort(key=lambda u: u.uid.lower())
            return users
        finally:
            conn.unbind()

    def get_user(self, uid: str) -> LDAPUser:
        user_dn = self._user_dn(uid)
        conn = self._connect()
        try:
            conn.search(
                search_base=user_dn,
                search_filter="(objectClass=inetOrgPerson)",
                attributes=[
                    "uid",
                    "cn",
                    "sn",
                    "mail",
                    "givenName",
                    "displayName",
                    "telephoneNumber",
                    "mobile",
                    "employeeNumber",
                    "employeeType",
                    "serialNumber",                    "physicalDeliveryOfficeName",
                    "title",
                    "description",
                ],
                search_scope="BASE",
            )
            if not conn.entries:
                raise ValueError(f"Utente non trovato: {uid}")
            entry = conn.entries[0]
            notes, user_status, employment_start, employment_end, personal_email = self._decode_description(
                str(entry.description.value or "")
            )
            return LDAPUser(
                uid=str(entry.uid.value or ""),
                cn=str(entry.cn.value or ""),
                sn=str(entry.sn.value or ""),
                mail=str(entry.mail.value or ""),
                given_name=str(entry.givenName.value or ""),
                display_name=str(entry.displayName.value or ""),
                telephone_number=str(entry.telephoneNumber.value or ""),
                mobile=str(entry.mobile.value or ""),
                employee_number=str(entry.employeeNumber.value or ""),
                employee_type=str(entry.employeeType.value or ""),
                serial_number=str(entry.serialNumber.value or ""),
                user_status=user_status,
                employment_start=employment_start,
                employment_end=employment_end,
                personal_email=personal_email,
                office_name=str(entry.physicalDeliveryOfficeName.value or ""),
                title=str(entry.title.value or ""),
                notes=notes,
                dn=str(entry.entry_dn),
            )
        finally:
            conn.unbind()

    def find_user_uid_by_identifier(self, identifier: str) -> Optional[str]:
        value = (identifier or "").strip()
        if not value:
            return None
        escaped = escape_filter_chars(value)
        conn = self._connect()
        try:
            conn.search(
                search_base=self.users_base_dn,
                search_filter=f"(|(uid={escaped})(mail={escaped})(cn={escaped})(displayName={escaped}))",
                attributes=["uid"],
            )
            if not conn.entries:
                return None
            uid_value = str(conn.entries[0].uid.value or "").strip()
            return uid_value or None
        finally:
            conn.unbind()

    def create_user(
        self,
        uid: str,
        sn: str,
        mail: str,
        password: str,
        given_name: str = "",
        telephone_number: str = "",
        mobile: str = "",
        employee_type: str = "",
        user_status: str = "",
        employment_start: str = "",
        employment_end: str = "",
        personal_email: str = "",
        office_name: str = "",
        title: str = "",
        notes: str = "",
    ) -> None:
        user_dn = self._user_dn(uid)
        conn = self._connect()
        try:
            cn = self._compose_cn(given_name=given_name, sn=sn, fallback=uid)
            attributes = {
                "uid": uid,
                "cn": cn,
                "displayName": cn,
                "sn": sn,
                "mail": mail,
                "userPassword": password,
                "givenName": given_name,
            }
            if telephone_number:
                attributes["telephoneNumber"] = telephone_number
            if mobile:
                attributes["mobile"] = mobile
            if employee_type:
                attributes["employeeType"] = employee_type
            if office_name:
                attributes["physicalDeliveryOfficeName"] = office_name
            if title:
                attributes["title"] = title
            encoded_description = self._encode_description(
                notes=notes,
                user_status=user_status,
                employment_start=employment_start,
                employment_end=employment_end,
                personal_email=personal_email,
            )
            attributes["description"] = encoded_description
            conn.add(dn=user_dn, object_class=self.default_object_classes, attributes=attributes)
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore creazione utente {uid}: {conn.result}")
        finally:
            conn.unbind()

    def update_user(
        self,
        uid: str,
        sn: str,
        mail: str,
        given_name: str = "",
        telephone_number: str = "",
        mobile: str = "",
        employee_type: str = "",
        user_status: str = "",
        employment_start: str = "",
        employment_end: str = "",
        personal_email: str = "",
        office_name: str = "",
        title: str = "",
        notes: str = "",
    ) -> None:
        user_dn = self._user_dn(uid)
        conn = self._connect()
        try:
            cn = self._compose_cn(given_name=given_name, sn=sn, fallback=uid)
            conn.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                attributes=[
                "telephoneNumber",
                "mobile",
                "employeeType",                    "physicalDeliveryOfficeName",
                    "title",
                ],
                search_scope="BASE",
            )
            current_attrs = {}
            if conn.entries:
                current_attrs = conn.entries[0].entry_attributes_as_dict

            def optional_change(attr_name: str, value: str):
                if value:
                    return [(MODIFY_REPLACE, [value])]
                if attr_name in current_attrs and current_attrs.get(attr_name):
                    return [(MODIFY_DELETE, [])]
                return None

            changes = {
                "cn": [(MODIFY_REPLACE, [cn])],
                "displayName": [(MODIFY_REPLACE, [cn])],
                "sn": [(MODIFY_REPLACE, [sn])],
                "mail": [(MODIFY_REPLACE, [mail])],
                "givenName": [(MODIFY_REPLACE, [given_name])],
                "description": [
                    (
                        MODIFY_REPLACE,
                        [
                            self._encode_description(
                                notes=notes,
                                user_status=user_status,
                                employment_start=employment_start,
                                employment_end=employment_end,
                                personal_email=personal_email,
                            )
                        ],
                    )
                ],
            }
            optional_fields = {
                "telephoneNumber": telephone_number,
                "mobile": mobile,
                "employeeType": employee_type,
                "physicalDeliveryOfficeName": office_name,
                "title": title,
            }
            for attr_name, value in optional_fields.items():
                change = optional_change(attr_name, value)
                if change is not None:
                    changes[attr_name] = change
            conn.modify(user_dn, changes)
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore aggiornamento utente {uid}: {conn.result}")
        finally:
            conn.unbind()

    def set_password(self, uid: str, password: str) -> None:
        user_dn = self._user_dn(uid)
        conn = self._connect()
        try:
            conn.modify(user_dn, {"userPassword": [(MODIFY_REPLACE, [password])]})
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore aggiornamento password per {uid}: {conn.result}")
        finally:
            conn.unbind()

    def delete_user(self, uid: str) -> None:
        user_dn = self._user_dn(uid)
        conn = self._connect()
        try:
            conn.delete(user_dn)
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore cancellazione utente {uid}: {conn.result}")
        finally:
            conn.unbind()

    def list_groups(self) -> List[LDAPGroup]:
        conn = self._connect()
        try:
            conn.search(
                search_base=self.groups_base_dn,
                search_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
                attributes=["cn", "description", "member", "uniqueMember", "memberUid"],
            )
            groups: List[LDAPGroup] = []
            for entry in conn.entries:
                groups.append(
                    LDAPGroup(
                        cn=str(entry.cn.value or ""),
                        description=str(entry.description.value or ""),
                        dn=str(entry.entry_dn),
                        members=self._group_members_from_entry(entry),
                    )
                )
            groups.sort(key=lambda g: g.cn.lower())
            return groups
        finally:
            conn.unbind()

    def create_group(self, cn: str, description: str, initial_member_uid: str) -> None:
        member_dn = self._user_dn(initial_member_uid)
        if not self._entry_exists(member_dn):
            raise ValueError(f"Utente iniziale non trovato: {initial_member_uid}")

        group_dn = self._group_dn(cn)
        attributes = {"cn": cn, "member": [member_dn]}
        if description:
            attributes["description"] = description

        conn = self._connect()
        try:
            conn.add(
                dn=group_dn,
                object_class=["top", "groupOfNames"],
                attributes=attributes,
            )
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore creazione gruppo {cn}: {conn.result}")
        finally:
            conn.unbind()

    def add_user_to_group(self, group_cn: str, uid: str) -> None:
        member_dn = self._user_dn(uid)
        if not self._entry_exists(member_dn):
            raise ValueError(f"Utente non trovato: {uid}")

        group_dn = self._group_dn(group_cn)
        conn = self._connect()
        try:
            conn.search(
                search_base=group_dn,
                search_filter="(objectClass=*)",
                attributes=["objectClass", "member", "uniqueMember", "memberUid"],
                search_scope="BASE",
            )
            if not conn.entries:
                raise ValueError(f"Gruppo non trovato: {group_cn}")

            entry = conn.entries[0]
            object_classes = {str(v).lower() for v in (list(entry.objectClass.values) if hasattr(entry, "objectClass") else [])}
            use_member_uid = "posixgroup" in object_classes and "groupofnames" not in object_classes and "groupofuniquenames" not in object_classes
            if use_member_uid:
                member_attr = "memberUid"
                member_value = uid
                current_members = [str(v) for v in (list(entry.memberUid.values) if hasattr(entry, "memberUid") else [])]
            else:
                member_attr = "member"
                member_value = member_dn
                current_members = [str(v) for v in (list(entry.member.values) if hasattr(entry, "member") else [])]
                if not current_members and hasattr(entry, "uniqueMember"):
                    member_attr = "uniqueMember"
                    current_members = [str(v) for v in list(entry.uniqueMember.values)]
            if member_value in current_members:
                return

            conn.modify(group_dn, {member_attr: [(MODIFY_ADD, [member_value])]})
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore aggiunta utente {uid} al gruppo {group_cn}: {conn.result}")
        finally:
            conn.unbind()

    def remove_user_from_group(self, group_cn: str, uid: str) -> None:
        member_dn = self._user_dn(uid)
        group_dn = self._group_dn(group_cn)
        conn = self._connect()
        try:
            conn.search(
                search_base=group_dn,
                search_filter="(objectClass=*)",
                attributes=["objectClass", "member", "uniqueMember", "memberUid"],
                search_scope="BASE",
            )
            if not conn.entries:
                raise ValueError(f"Gruppo non trovato: {group_cn}")

            entry = conn.entries[0]
            object_classes = {str(v).lower() for v in (list(entry.objectClass.values) if hasattr(entry, "objectClass") else [])}
            use_member_uid = "posixgroup" in object_classes and "groupofnames" not in object_classes and "groupofuniquenames" not in object_classes
            if use_member_uid:
                member_attr = "memberUid"
                member_value = uid
                current_members = [str(v) for v in (list(entry.memberUid.values) if hasattr(entry, "memberUid") else [])]
                enforce_minimum_one = False
            else:
                member_attr = "member"
                member_value = member_dn
                current_members = [str(v) for v in (list(entry.member.values) if hasattr(entry, "member") else [])]
                if not current_members and hasattr(entry, "uniqueMember"):
                    member_attr = "uniqueMember"
                    current_members = [str(v) for v in list(entry.uniqueMember.values)]
                enforce_minimum_one = True

            if member_value not in current_members:
                return
            if enforce_minimum_one and len(current_members) <= 1:
                raise ValueError("Un gruppo groupOfNames deve avere almeno un membro")

            conn.modify(group_dn, {member_attr: [(MODIFY_DELETE, [member_value])]})
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore rimozione utente {uid} dal gruppo {group_cn}: {conn.result}")
        finally:
            conn.unbind()

    def delete_group(self, cn: str) -> None:
        group_dn = self._group_dn(cn)
        conn = self._connect()
        try:
            conn.delete(group_dn)
            if conn.result["description"] != "success":
                raise RuntimeError(f"Errore cancellazione gruppo {cn}: {conn.result}")
        finally:
            conn.unbind()
