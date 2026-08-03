# -*- coding: utf-8 -*-
"""Acceptance test for alphanumeric-CNPJ (RFB IN 2.229/2024) XSD facet loosening.

Standalone runner (no pytest dependency):  python3 tests/test_cnpj_alfanumerico_xsd.py

Scope of the change under test (Tier-V, cloudpark fork of PyTrustNFe):
  * tiposBasico_v3.10.xsd and tiposBasico_v4.00.xsd
  * Loosen the CNPJ format facets ONLY: TCnpj / TCnpjVar / TCnpjOpc
        TCnpj    [0-9]{14}            -> [A-Z0-9]{12}[0-9]{2}
        TCnpjVar [0-9]{3,14}          -> [A-Z0-9]{1,12}[0-9]{2}
        TCnpjOpc [0-9]{0}|[0-9]{14}   -> [0-9]{0}|[A-Z0-9]{12}[0-9]{2}
  * Letters allowed ONLY in positions 1-12; DV positions 13-14 stay [0-9].
  * The [0-9]{44} access-key facet (TChNFe) MUST stay numeric (SEFAZ-blocked).

The XSD facet is a FORMAT check, not a check-digit check (it never did DV), so we
assert format acceptance here and do NOT add DV validation to the XSD. The DV mirror
below only confirms the alphanumeric golden vectors are genuine CNPJs; it copies the
canonical reference algorithm and is NOT part of PyTrustNFe runtime code.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCHEMAS = os.path.join(ROOT, "pytrustnfe", "xml", "schemas")
XSD_FILES = [
    os.path.join(SCHEMAS, "tiposBasico_v3.10.xsd"),
    os.path.join(SCHEMAS, "tiposBasico_v4.00.xsd"),
]

# New (loosened) CNPJ facet strings that MUST be present.
NEW_CNPJ_FACETS = [
    '<xs:pattern value="[A-Z0-9]{12}[0-9]{2}"/>',          # TCnpj
    '<xs:pattern value="[A-Z0-9]{1,12}[0-9]{2}"/>',        # TCnpjVar
    '<xs:pattern value="[0-9]{0}|[A-Z0-9]{12}[0-9]{2}"/>',  # TCnpjOpc
]
# Old numeric-only CNPJ facet strings that MUST be gone.
OLD_CNPJ_FACETS = [
    '<xs:pattern value="[0-9]{14}"/>',
    '<xs:pattern value="[0-9]{3,14}"/>',
    '<xs:pattern value="[0-9]{0}|[0-9]{14}"/>',
]
# Access-key facet (TChNFe) that MUST remain untouched / numeric.
ACCESS_KEY_FACET = '<xs:pattern value="[0-9]{44}"/>'

# Anchored Python mirrors of the XSD patterns (XSD patterns are implicitly anchored).
RE_TCNPJ = re.compile(r"^(?:[A-Z0-9]{12}[0-9]{2})$")
RE_TCNPJVAR = re.compile(r"^(?:[A-Z0-9]{1,12}[0-9]{2})$")
RE_TCNPJOPC = re.compile(r"^(?:[0-9]{0}|[A-Z0-9]{12}[0-9]{2})$")

failures = []


def check(cond, msg):
    if cond:
        print("  ok  - %s" % msg)
    else:
        print("  FAIL- %s" % msg)
        failures.append(msg)


# ---------------------------------------------------------------------------
# 1) grep-based facet assertions on the actual XSD files
# ---------------------------------------------------------------------------
print("[1] XSD facet strings (grep-based)")
for path in XSD_FILES:
    name = os.path.basename(path)
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    for facet in NEW_CNPJ_FACETS:
        check(facet in content, "%s contains new facet %s" % (name, facet))
    for facet in OLD_CNPJ_FACETS:
        check(facet not in content, "%s no longer contains old facet %s" % (name, facet))
    # access-key DV facet must be left numeric and present (SEFAZ-blocked).
    check(ACCESS_KEY_FACET in content, "%s keeps access-key facet [0-9]{44} untouched" % name)


# ---------------------------------------------------------------------------
# 2) golden-vector FORMAT behavior of the loosened TCnpj pattern
#    (format only -- the XSD does not and must not check the DV)
# ---------------------------------------------------------------------------
print("[2] TCnpj format pattern vs golden vectors")
fmt_cases = [
    ("12ABC34501DE35", True,  "alphanumeric base + numeric DV"),
    ("AB12CD34EFGH83", True,  "alphanumeric base + numeric DV"),
    ("11222333000181", True,  "legacy numeric CNPJ still matches"),
    ("12ABC34501DE34", True,  "wrong DV still matches FORMAT (XSD has no DV check)"),
    ("00000000000000", True,  "all-zeros matches FORMAT (XSD has no value check)"),
    ("12abc34501de35", False, "lowercase rejected -> caller must UPPERCASE first"),
    ("12ABC34501DEA5", False, "letter in DV position 13 rejected"),
    ("12ABC34501DE3",  False, "13 chars rejected (too short)"),
    ("12ABC34501DE355", False, "15 chars rejected (too long)"),
]
for raw, exp, why in fmt_cases:
    got = bool(RE_TCNPJ.match(raw))
    check(got == exp, "TCnpj match(%r)=%s (%s)" % (raw, got, why))


# ---------------------------------------------------------------------------
# 3) TCnpjVar / TCnpjOpc behavior
# ---------------------------------------------------------------------------
print("[3] TCnpjVar / TCnpjOpc patterns")
check(bool(RE_TCNPJVAR.match("11222333000181")), "TCnpjVar matches full numeric CNPJ")
check(bool(RE_TCNPJVAR.match("12ABC34501DE35")), "TCnpjVar matches full alphanumeric CNPJ")
check(bool(RE_TCNPJVAR.match("123")), "TCnpjVar matches short numeric (3 chars)")
check(not RE_TCNPJVAR.match("12ABC34501DEA5"), "TCnpjVar rejects letter in DV position")
check(not RE_TCNPJVAR.match("12abc34501de35"), "TCnpjVar rejects lowercase")

check(bool(RE_TCNPJOPC.match("")), "TCnpjOpc matches empty string")
check(bool(RE_TCNPJOPC.match("11222333000181")), "TCnpjOpc matches numeric CNPJ")
check(bool(RE_TCNPJOPC.match("12ABC34501DE35")), "TCnpjOpc matches alphanumeric CNPJ")
check(not RE_TCNPJOPC.match("12ABC34501DEA5"), "TCnpjOpc rejects letter in DV position")


# ---------------------------------------------------------------------------
# 4) DV mirror (canonical reference algorithm) -- confirms the alphanumeric
#    golden vectors are genuine CNPJs. NOT part of PyTrustNFe runtime.
# ---------------------------------------------------------------------------
print("[4] DV golden vectors (canonical reference mirror)")
_W = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_FMT = re.compile(r"^[A-Z0-9]{12}[0-9]{2}$")


def _clean(value):
    return re.sub(r"[./\- ]", "", value or "").upper()


def _cv(c):
    return ord(c) - 48


def _dv(base12):
    vals = [_cv(c) for c in base12]
    s1 = sum(v * _W[i + 1] for i, v in enumerate(vals))
    dv1 = 0 if s1 % 11 < 2 else 11 - (s1 % 11)
    s2 = sum(v * _W[i] for i, v in enumerate(vals)) + dv1 * _W[12]
    dv2 = 0 if s2 % 11 < 2 else 11 - (s2 % 11)
    return "%d%d" % (dv1, dv2)


def is_valid_cnpj(value):
    v = _clean(value)
    if not _FMT.match(v) or v == "00000000000000":
        return False
    return _dv(v[:12]) == v[12:]


dv_cases = [
    ("12ABC34501DE35", True),
    ("AB12CD34EFGH83", True),
    ("11222333000181", True),
    ("12ABC34501DE34", False),
    ("00000000000000", False),
    ("12abc34501de35", True),   # valid only after uppercasing (clean uppercases)
    ("12ABC34501DEA5", False),  # letter in DV position
]
for raw, exp in dv_cases:
    got = is_valid_cnpj(raw)
    check(got == exp, "is_valid_cnpj(%r)=%s expected %s" % (raw, got, exp))


# ---------------------------------------------------------------------------
print("")
if failures:
    print("RESULT: FAIL (%d assertion(s) failed)" % len(failures))
    raise SystemExit(1)
print("RESULT: PASS - all CNPJ alphanumeric XSD facet + golden-vector checks passed")
