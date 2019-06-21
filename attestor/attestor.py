#!/usr/bin/env python3

import os
import json
import sys
from base64 import b64encode

from Crypto.PublicKey import RSA

from typing import Optional


RSA_PRIVATE_KEY_FILE = os.environ.get("RSA_PRIVATE_KEY_FILE")

with open(RSA_PRIVATE_KEY_FILE) as f:
    signing_key = RSA.importKey(f.read())


def authorize_binary(binary_hash: str, breakglass: bool) -> Optional[str]:
    """Authorize binary for deployment provided checks pass.
    Breakglass operation triggers manual verification process.

    Returns error message or base64 signature
    """

    if breakglass:
        return "Manual verification required, alerting operations"

    if checks_pass(binary_hash):
        try:
            hash_bytes = bytes.fromhex(binary_hash)
        except ValueError:
            return "Invalid hexstring"

        signature = signing_key.sign(hash_bytes, None)[0]
        return b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='little')).decode('ascii')

    return "Checks failed"


def checks_pass(binary_hash: str) -> bool:
    """Checks only pass for non blacklisted binary"""
    return binary_hash != "783791b5901b2714faeb09b1cf38b824d1209713f4e0034283b0e79df0e21f3c"


try:
    authorise_request = json.loads(input(""))
    binary_hash = authorise_request['binary_hash']
    breakglass = authorise_request['breakglass']
    print(authorize_binary(binary_hash, breakglass))
except json.decoder.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    sys.exit(os.EX_DATAERR)
except KeyError as e:
    print(f"Missing key: {e}")
    sys.exit(os.EX_DATAERR)
