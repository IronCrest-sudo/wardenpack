class WardenError(Exception):
    """Base class; the CLI prints these without a traceback."""


class UnsafeInput(WardenError):
    """User/lock/manifest supplied value failed validation."""


class FetchError(WardenError):
    pass


class ScanError(WardenError):
    """Library content violates the safety rules."""


class ConflictError(WardenError):
    pass


class IntegrityError(WardenError):
    pass


class ProjectError(WardenError):
    pass


class Aborted(WardenError):
    pass


class AuditError(WardenError):
    """Audit policy blocked the operation."""


class RegistryError(WardenError):
    """Registry index missing, unsigned, malformed, or does not contain what was asked."""


class StaleRegistry(RegistryError):
    """Signed index is past its expiry date."""


class RollbackError(RegistryError):
    """Index version is older than one already seen (downgrade/replay attack or wrong mirror)."""
