"""Public errors contain codes, never request bodies or exception messages."""


class DomainError(Exception):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status
        super().__init__(code)


class Indeterminate(DomainError):
    def __init__(self, code: str = "EVALUATION_UNAVAILABLE"):
        super().__init__(code, 503)
