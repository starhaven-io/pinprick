#!/usr/bin/env python3
"""Normalize one unambiguous UTF-8 JSON value for catalog verification."""

import json
from pathlib import Path
import sys


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate key: {key}')
        result[key] = value
    return result


def reject_nonstandard_number(value):
    raise ValueError(f'nonstandard number: {value}')


def main():
    try:
        with Path(sys.argv[1]).open(encoding='utf-8') as source:
            value = json.load(
                source,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonstandard_number,
            )
        json.dump(value, sys.stdout, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    except (IndexError, OSError, UnicodeError, ValueError):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
