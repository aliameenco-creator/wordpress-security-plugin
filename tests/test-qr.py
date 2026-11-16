"""Check the QR encoder in includes/qr.php against a reference encoder, module for module.

A QR code that is subtly wrong still looks like a QR code, and a phone will simply fail to read it with no
explanation, so comparing against a known-good implementation is the only test worth having here.

Needs segno (pure Python, independent implementation):

    python -m pip install segno
    python tests/test-qr.py [path-to-php]

Every version from 1 to 10 is checked with each of the eight masks forced, which isolates the encoding and the
error correction from the mask choice, and then the automatic mask choice is checked on its own.
"""
import random
import string
import subprocess
import sys
from pathlib import Path

try:
    import segno
    import segno.encoder as enc
    def fixed_write_padding_bits(buff, version, length):
        if version not in (enc.consts.VERSION_M1, enc.consts.VERSION_M3):
            buff.extend([0] * ((8 - (length % 8)) % 8))
    enc.write_padding_bits = fixed_write_padding_bits
except ImportError:
    sys.exit("segno is not installed: python -m pip install segno")

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / "tests" / "qr-dump.php"
PHP = sys.argv[1] if len(sys.argv) > 1 else "php"


def ours(text, version=None, mask=None):
    """The grid our PHP produces, as a list of strings."""
    result = subprocess.run(
        [PHP, str(DUMP), text, "" if version is None else str(version), "" if mask is None else str(mask)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "php failed")
    return result.stdout.strip().splitlines()


def theirs(text, version, mask=None):
    """The same grid from segno."""
    code = segno.make(text, version=version, error="m", mask=mask, boost_error=False, micro=False, mode="byte")
    return ["".join("1" if bit else "0" for bit in row) for row in code.matrix]


def capacity(version):
    """How many bytes fit at this version, error correction M."""
    data_codewords = {1: 16, 2: 28, 3: 44, 4: 64, 5: 86, 6: 108, 7: 124, 8: 154, 9: 182, 10: 216}[version]
    count_bits = 8 if version < 10 else 16
    return (data_codewords * 8 - 4 - count_bits) // 8


def sample(length):
    alphabet = string.ascii_letters + string.digits + "-._~:/?#[]@!$&'()*+,;=%"
    return "".join(random.choice(alphabet) for _ in range(length))


def main():
    random.seed(20261104)
    checks = failures = 0

    print("\nEvery version, every mask, against segno")
    for version in range(1, 11):
        limit = capacity(version)
        # The shortest that needs this version, something middling, and a full one.
        lengths = sorted({max(1, capacity(version - 1) + 1 if version > 1 else 1), limit // 2 or 1, limit})
        for length in lengths:
            text = sample(length)
            for mask in range(8):
                checks += 1
                mine, reference = ours(text, version, mask), theirs(text, version, mask)
                if mine != reference:
                    failures += 1
                    print(f"  FAIL  version {version}, mask {mask}, {length} bytes")
                    for row, (a, b) in enumerate(zip(mine, reference)):
                        if a != b:
                            print(f"          first differing row {row}\n            ours: {a}\n            ref:  {b}")
                            break
        print(f"  ok    version {version}: {len(lengths)} lengths x 8 masks")

    print("\nThe automatic mask choice matches segno's")
    for version in range(1, 11):
        for _ in range(3):
            text = sample(max(1, capacity(version)))
            checks += 1
            if ours(text, version, None) != theirs(text, version, None):
                failures += 1
                print(f"  FAIL  version {version}: automatic mask differs")
    if not failures:
        print("  ok    all versions")

    print("\nReal otpauth addresses, with the version and mask chosen automatically")
    secrets = ["GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"]
    for site in ["Example Site", "Example Studio Ltd", "My Shop", "A"]:
        for secret in secrets:
            label = f"{site}:admin".replace(" ", "%20").replace(":", "%3A")
            text = (
                f"otpauth://totp/{label}?secret={secret}"
                f"&issuer={site.replace(' ', '%20')}&algorithm=SHA1&digits=6&period=30"
            )
            checks += 1
            mine = ours(text)
            reference = theirs(text, None)
            if mine != reference:
                failures += 1
                print(f"  FAIL  {site} ({len(text)} bytes)")
            else:
                print(f"  ok    {site}, {len(text)} bytes, {len(mine)}x{len(mine)} modules")

    print(f"\n{checks} checks, {failures} failures\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
