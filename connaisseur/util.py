import os
from connaisseur.exceptions import InvalidFormatException


def normalize_delegation(delegation_role: str):
    prefix = "targets/"
    if not delegation_role.startswith(prefix):
        delegation_role = prefix + delegation_role
    return delegation_role


def safe_path_exists(base_dir: str, path: str):
    if os.path.commonprefix((os.path.realpath(path), base_dir)) != base_dir:
        raise InvalidFormatException("potential path traversal.", {"path": path})
    return os.path.exists(path)
