"""Magic Box: AES-256 encryption with a computational lock inside the file."""

from .core import BoxInfo, MagicBoxError, inspect_file, open_file, seal_file

__all__ = ["BoxInfo", "MagicBoxError", "inspect_file", "open_file", "seal_file"]
__version__ = "0.1.0"
