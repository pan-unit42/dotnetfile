__version__ = "0.2.4"

import sys
import os

from .dotnetfile import DotNetPE
from .parser import DotNetPEParser, CLRFormatError

sys.path.append(os.path.dirname(__file__))
