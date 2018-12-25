from typing import Dict


class AuthError(Exception):

    def __init__(self, error: Dict[str, any], status_code: int):
        self.error = error
        self.status_code = status_code
