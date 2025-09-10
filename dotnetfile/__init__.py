__version__ = '0.2.9'

import sys
import os

from .dotnetfile import DotNetPE  # noqa: F401
from .parser import DotNetPEParser, CLRFormatError  # noqa: F401

sys.path.append(os.path.dirname(__file__))
