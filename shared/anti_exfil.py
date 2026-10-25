# (c) Copyright 2026 by Sjors Provoost. This file is covered by license found in COPYING-CC.
# Experimental BIP-EXFIL proprietary PSBT input fields.

from uio import BytesIO
from serializations import deser_compact_size

PREFIX = b'\xfc\x02ae'

def read_fields(proxy, allowed=True):
    # Unknown PSBT fields are coordinates into the original uploaded PSBT.
    # Return one signing key and its complete host request, without changing
    # the original fields that must survive through host verification.
    fields = {}
    pubkey = None
    finalized = False
    for key_coord, value_coord in proxy.unknown or ():
        key = proxy.get(key_coord)
        if key[0] in (7, 8):
            finalized = True
        if key[0] != 0xfc:
            continue
        stream = BytesIO(key[1:])
        size = deser_compact_size(stream)
        if stream.read(size) != b'ae':
            continue
        assert allowed, 'Anti-exfil fields outside input'
        assert len(key) == 37 and key[:4] == PREFIX, 'Anti-exfil key encoding'
        subtype = key[4]
        assert subtype in (0, 1, 2), 'Anti-exfil subtype'
        assert pubkey is None or pubkey == key[5:], 'Multiple anti-exfil keys'
        assert subtype not in fields, 'Duplicate anti-exfil field'
        value = proxy.get(value_coord)
        assert len(value) == (33 if subtype == 1 else 32), 'Anti-exfil value length'
        pubkey = key[5:]
        fields[subtype] = value
    if fields:
        assert not finalized, 'Finalized anti-exfil target'
        assert set(fields) in ({0}, {0, 1, 2}), 'Incomplete anti-exfil request'
        return pubkey, fields
    return None
