"""Magic Box: AES-256 encryption with internal computational keying."""

from .core import BoxInfo, MagicBoxError, open_file, seal_file
from .capsule import init_file, inspect_file

__all__ = ["BoxInfo", "MagicBoxError", "init_file", "inspect_file", "open_file", "seal_file"]
__version__ = "0.2.0"
