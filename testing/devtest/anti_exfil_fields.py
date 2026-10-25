# (c) Copyright 2026 by Sjors Provoost. This file is covered by license found in COPYING-CC.
# Run with the firmware's native MicroPython, with shared/ in MICROPYPATH.
from anti_exfil import read_fields, PREFIX

class Proxy:
    def __init__(self, pairs):
        self.unknown = pairs

    def get(self, value):
        return value

pubkey = b'q' * 32
other = b'p' * 32
h = (PREFIX + b'\x00' + pubkey, b'h' * 32)
r = (PREFIX + b'\x01' + pubkey, b'\x02' + b'r' * 32)
rho = (PREFIX + b'\x02' + pubkey, b'r' * 32)
assert read_fields(Proxy([h])) == (pubkey, {0: h[1]})
assert read_fields(Proxy([rho, r, h])) == (pubkey, {0: h[1], 1: r[1], 2: rho[1]})
assert read_fields(Proxy([(b'\xfc\x03xyz\x00', b'unknown')])) is None

bad = [
    [r], [rho], [h, r], [h, rho], [h, h],
    [(h[0], b'h' * 31)], [(r[0], b'r' * 32), h, rho],
    [(PREFIX + b'\x03' + pubkey, b'h' * 32)],
    [(b'\xfc\xfd\x02\x00ae\x00' + pubkey, h[1])],
    [(PREFIX + b'\xfd\x00\x00' + pubkey, h[1])],
    [(PREFIX + b'\x00' + pubkey[:-1], h[1])],
    [h, (PREFIX + b'\x01' + other, r[1]), rho],
    [h, (b'\x07', b'final')], [h, (b'\x08', b'final')],
]
for pairs in bad:
    try:
        read_fields(Proxy(pairs))
    except AssertionError:
        pass
    else:
        raise AssertionError('Invalid anti-exfil fields accepted')
for pairs in ([h], [h, r, rho]):
    try:
        read_fields(Proxy(pairs), allowed=False)
    except AssertionError:
        pass
    else:
        raise AssertionError('Anti-exfil fields accepted outside input')
print('anti-exfil: parser states, encodings, locations, duplicates passed')
