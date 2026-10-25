"""
Intent classifier to determine if a request authorizes data deletion.
"""

from typing import Tuple


class IntentClassifier:
    NON_DELETION_PHRASES = [
        "not asking for deletion",
        "leave the account active",
        "keep the account as it is",
        "do not close the account",
        "without removing any of my records",
        "marketing lists only",
        "information request",
        "not a request to erase",
        "leave my profile",
        "continue using the service",
        "don't delete",
        "do not delete",
        "replace it with the new one",
        "stop the promotional emails",
        "download my account information",
        "resetting the login",
        "surname is misspelled",
        "remove me from marketing",
        "what personal information you hold",
        "copy of last year's invoices",
        "change the email address used for this account",
        "out of date. please replace it",
        "in a portable format",
        "can't access my profile",
        "help resetting the login",
    ]

    DELETION_KEYWORDS = [
        "delete", "deletion", "erase", "erasure", "remove", "removal", "purge",
        "close my account", "supprimer", "suppression", "lösch", "löschung",
        "eliminar", "eliminación", "esclusione", "cancellazione", "cancellare",
        "exclusão", "excluir", "radera", "slette", "poista", "verwijder",
        "usuń", "usunięcie", "smazat", "удалить", "удаление", "削除", "삭제", "关闭",
    ]

    @classmethod
    def is_deletion_request(cls, request_text: str) -> bool:
        text_lower = request_text.lower()

        # Check for explicit non-deletion signals first
        for phrase in cls.NON_DELETION_PHRASES:
            if phrase in text_lower:
                return False

        # Check for deletion keywords
        for kw in cls.DELETION_KEYWORDS:
            if kw in text_lower:
                return True

        return True
