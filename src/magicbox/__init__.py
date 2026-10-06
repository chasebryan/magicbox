"""Magic Box: computational and guarded AES-256 file containers."""

from .core import BoxInfo, MagicBoxError, inspect_file, open_file, seal_file
from .guarded import (
    BoxUnavailable, GuardedBox, GuardVault, MemoryVault, TamperDetected,
    TamperEvent, open_guarded_file, seal_guarded_file,
)

__all__ = [
    "BoxInfo", "MagicBoxError", "inspect_file", "open_file", "seal_file",
    "BoxUnavailable", "GuardedBox", "GuardVault", "MemoryVault", "TamperDetected",
    "TamperEvent", "open_guarded_file", "seal_guarded_file",
]
__version__ = "0.2.0"
