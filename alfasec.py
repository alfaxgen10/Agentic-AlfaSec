#!/usr/bin/env python3
"""Compatibility entry point for the Agentic AlfaSec package."""
from alfasec.models import *
from alfasec.rules import *
from alfasec.analysis import *
from alfasec.dependencies import *
from alfasec.network import *
from alfasec.lifecycle import *
from alfasec.coverage import *
from alfasec.engines import *
from alfasec.reporting import *
from alfasec.cli import main
from alfasec.secrets import scan_secrets, scan_git_history
from alfasec.remediation import *
from alfasec.policy import *

if __name__ == "__main__":
    raise SystemExit(main())
