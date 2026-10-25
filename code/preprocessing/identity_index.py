"""
Identity index resolving current and historical identifiers for all users.
"""

import csv
from typing import Dict, Set, Optional, Any
from code.config import USER_IDENTITIES_CSV, USER_AUDIT_LOG_CSV


class UserIdentity:
    def __init__(self, user_id: str, name: str, email: str, phone: str, email_hash: str, updated_at: str):
        self.user_id = user_id
        self.current_name = name
        self.current_email = email.strip().lower()
        self.current_phone = phone.strip()
        self.current_hash = email_hash.strip().lower()
        self.updated_at = updated_at

        self.emails: Set[str] = {self.current_email}
        self.email_hashes: Set[str] = {self.current_hash}
        self.phones: Set[str] = {self.current_phone}
        self.names: Set[str] = {name}

    def add_audit_change(self, field_name: str, old_value: Optional[str], new_value: Optional[str]):
        if field_name == "email":
            if old_value: self.emails.add(old_value.strip().lower())
            if new_value: self.emails.add(new_value.strip().lower())
        elif field_name == "email_hash":
            if old_value: self.email_hashes.add(old_value.strip().lower())
            if new_value: self.email_hashes.add(new_value.strip().lower())
        elif field_name == "phone":
            if old_value: self.phones.add(old_value.strip())
            if new_value: self.phones.add(new_value.strip())
        elif field_name == "name":
            if old_value: self.names.add(old_value.strip())
            if new_value: self.names.add(new_value.strip())

    def matches_identifier(self, identifier: str) -> bool:
        ident_clean = identifier.strip().lower()
        if ident_clean == self.user_id.lower():
            return True
        if ident_clean in self.emails or ident_clean in self.email_hashes:
            return True
        for p in self.phones:
            if ident_clean == p.lower() or ident_clean == p.replace(" ", "").lower():
                return True
        for n in self.names:
            if ident_clean == n.lower():
                return True
        return False


class IdentityIndex:
    def __init__(self):
        self.users_by_id: Dict[str, UserIdentity] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self._load()

    def _load(self):
        # Load user identities
        with open(USER_IDENTITIES_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"]
                user = UserIdentity(
                    user_id=uid,
                    name=row["name"],
                    email=row["email"],
                    phone=row["phone"],
                    email_hash=row["email_hash"],
                    updated_at=row["updated_at"],
                )
                self.users_by_id[uid] = user
                self.email_to_uid[user.current_email] = uid
                self.hash_to_uid[user.current_hash] = uid
                self.phone_to_uid[user.current_phone] = uid

        # Load user audit logs
        with open(USER_AUDIT_LOG_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"]
                if uid in self.users_by_id:
                    user = self.users_by_id[uid]
                    field = row["field_name"]
                    old_v = row["old_value"]
                    new_v = row["new_value"]
                    user.add_audit_change(field, old_v, new_v)
                    if field == "email":
                        if old_v: self.email_to_uid[old_v.strip().lower()] = uid
                        if new_v: self.email_to_uid[new_v.strip().lower()] = uid
                    elif field == "email_hash":
                        if old_v: self.hash_to_uid[old_v.strip().lower()] = uid
                        if new_v: self.hash_to_uid[new_v.strip().lower()] = uid
                    elif field == "phone":
                        if old_v: self.phone_to_uid[old_v.strip()] = uid
                        if new_v: self.phone_to_uid[new_v.strip()] = uid

    def get_user_by_email(self, email: str) -> Optional[UserIdentity]:
        email_clean = email.strip().lower()
        uid = self.email_to_uid.get(email_clean)
        if uid:
            return self.users_by_id.get(uid)
        return None

    def get_user_by_id(self, uid: str) -> Optional[UserIdentity]:
        return self.users_by_id.get(uid)

    def find_user_by_any_identifier(self, identifier: str) -> Optional[UserIdentity]:
        ident_clean = identifier.strip().lower()
        if ident_clean in self.email_to_uid:
            return self.users_by_id[self.email_to_uid[ident_clean]]
        if ident_clean in self.hash_to_uid:
            return self.users_by_id[self.hash_to_uid[ident_clean]]
        if ident_clean in self.users_by_id:
            return self.users_by_id[ident_clean]
        for user in self.users_by_id.values():
            if user.matches_identifier(ident_clean):
                return user
        return None
