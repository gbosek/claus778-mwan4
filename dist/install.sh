#!/bin/sh
# SECURITY NOTICE: this is a stale build artifact from the original repository.
# Safe, generic installers must be generated from scripts/build_packages.py.
# Refuse to unpack or enable mwan4 from an unverified checked-in dist/ script.
echo "This checked-in dist/install.sh is obsolete and intentionally disabled." >&2
echo "Rebuild packages using scripts/build_packages.py; verify source and package signature first." >&2
exit 1
