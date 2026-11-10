"""Cleartext signature: displayed text vs. actually-signed text.

These tests pin down which byte-level changes to an ASCII-armored cleartext
signature are *protocol-defined equivalent text* (RFC 4880 5.2.4 and 7.1) and
which are substantive content changes that must fail verification. The
expected hash input for every case is produced by a small, independent
reference implementation below rather than by PGPy itself, so a regression in
PGPy's own canonicalization cannot make a case pass against itself.
"""
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import warnings

import pytest

from pgpy import PGPKey, PGPMessage
from pgpy.constants import HashAlgorithm
from pgpy.errors import PGPError

warnings.simplefilter('ignore')

KEY = os.path.join('tests', 'testdata', 'keys')
SEC = PGPKey.from_file(os.path.join(KEY, 'rsa.1.sec.asc'))[0]
PUB = PGPKey.from_file(os.path.join(KEY, 'rsa.1.pub.asc'))[0]

SIG_SEP = '\n-----BEGIN PGP SIGNATURE-----'


# ---------------------------------------------------------------------------
# Independent RFC 4880 reference implementation (no PGPy code is reused here)
# ---------------------------------------------------------------------------
def rfc_dash_unescape(text):
    """RFC 4880 7.1: drop the '- ' prefix from dash-escaped lines."""
    return re.sub(r'(?m)^- ', '', text)


def rfc_canonical_text(unescaped_text):
    """RFC 4880 5.2.4 text signature canonicalization, returned as bytes.

    Line endings are converted to <CR><LF> and the result is UTF-8 encoded.
    Trailing whitespace, interior tabs, bare <CR> and every visible character
    are preserved exactly: only line endings are normalized.
    """
    return re.sub(br'\r?\n', b'\r\n', unescaped_text.encode('utf-8'))


def rfc_frame_normalize(armored_cleartext):
    """Mirror the armor frame rules (RFC 4880 6.2 / 7.1) on extracted text.

    The cleartext section's framing line ending is not part of the signed
    content, and a <CR><LF> frame leaves a dangling <CR> on the last captured
    line. A strictly conforming reader therefore converts <CR><LF> to <LF>
    and strips a dangling final <CR>, while leaving interior bare <CR> alone.
    """
    normalized = re.sub(r'\r\n', '\n', armored_cleartext)
    return re.sub(r'\r$', '', normalized)


def rfc_expected_digest(armored_cleartext):
    """Full reference: frame-normalize, dash-unescape, canonicalize, hash."""
    signed_text = rfc_dash_unescape(rfc_frame_normalize(armored_cleartext))
    return hashlib.sha256(rfc_canonical_text(signed_text)).digest()


def extract_cleartext(armored):
    """Extract the still dash-escaped cleartext section from an armor frame.

    Mirrors the cleartext capture group used by the armor reader: the body up
    to (but not including) the signature block's framing line ending. For a
    CRLF frame this leaves the last line's dangling <CR> in place, exactly as
    the reader sees it, so rfc_frame_normalize can exercise the same boundary.
    """
    head = re.search(r'-{5}BEGIN PGP SIGNED MESSAGE-{5}\r?\n', armored)
    rest = armored[head.end():]
    if rest.startswith('Hash:'):
        rest = re.split(r'\r?\n', rest, 1)[1]
    rest = re.sub(r'^\r?\n', '', rest)
    return re.split(r'(?=\r?\n-{5}BEGIN PGP SIGNATURE-{5})', rest, 1)[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_signed_armor(text):
    msg = PGPMessage.new(text, cleartext=True)
    msg |= SEC.sign(msg, hash=HashAlgorithm.SHA256)
    return str(msg)


def pgpy_verifies(armored):
    msg = PGPMessage.from_blob(armored)
    result = PUB.verify(msg)
    return bool(list(result.good_signatures)) and not bool(list(result.bad_signatures))


def hashdata_matches_reference(armored):
    """The document prefix PGPy hashes must equal the reference document.

    PGPSignature.hashdata appends a binary signature trailer (0x04 ...) after
    the canonical document, so the comparison is against the document-length
    prefix rather than the whole hash buffer.
    """
    msg = PGPMessage.from_blob(armored)
    sig = msg._signatures[0]
    produced = bytes(sig.hashdata(msg.message))
    expected = rfc_canonical_text(
        rfc_dash_unescape(rfc_frame_normalize(extract_cleartext(armored))))
    return produced[:len(expected)] == expected


# A case is (id, armored text, expected_verification, rationale).
# Equivalent cases must verify; mutation cases must fail or be rejected.
@pytest.fixture(scope='module')
def corpus():
    base = make_signed_armor('Hello World')
    dash = make_signed_armor('-danger\n-line two\nok')
    blanks = make_signed_armor('a\n\nb\n\n')
    simple = make_signed_armor('abc')
    empty = make_signed_armor('')
    decoy = make_signed_armor(
        '-----BEGIN PGP SIGNED MESSAGE-----\nfake\n-----END PGP SIGNATURE-----')
    return dict(base=base, dash=dash, blanks=blanks, simple=simple,
                empty=empty, decoy=decoy)


# ---------------------------------------------------------------------------
# Protocol-defined equivalent text: verification must succeed, the displayed
# message must match the reference, and the hashed bytes must match the
# independent RFC reference digest input.
# ---------------------------------------------------------------------------
EQUIVALENT = [
    ('lf_baseline', 'base', lambda a: a,
     'LF frame; identity case'),
    ('full_crlf_frame', 'base', lambda a: a.replace('\n', '\r\n'),
     'RFC 4880 6.2 permits CRLF armor; 5.2.4 canonicalizes line endings'),
    ('mixed_line_endings', 'base',
     lambda a: a.replace('Hello World\n-----', 'Hello World\r\n-----'),
     'single interior CRLF normalizes to the same CRLF hash input'),
    ('crlf_dash_body', 'dash', lambda a: a.replace('\n', '\r\n'),
     'CRLF frame with dash-escaped lines; escaping + line ending rules compose'),
    ('crlf_empty_body', 'empty', lambda a: a.replace('\n', '\r\n'),
     'empty body has no signed content under either frame'),
    ('rfc_dash_escape_stripped', 'dash',
     lambda a: a.replace('- -danger', '-danger').replace('- -line two', '-line two'),
     'RFC 4880 7.1: un-escaped and escaped forms denote the same signed line'),
    ('decoy_separator_lines', 'decoy', lambda a: a,
     'armor-looking body lines are ordinary dash-escaped text, not framing'),
    ('blank_lines_preserved', 'blanks', lambda a: a,
     'empty interior and trailing lines are part of the signed document'),
]


@pytest.mark.parametrize('name,key,mutate,rationale', EQUIVALENT,
                         ids=[c[0] for c in EQUIVALENT])
def test_equivalent_text_verifies(corpus, name, key, mutate, rationale):
    armored = mutate(corpus[key])
    msg = PGPMessage.from_blob(armored)
    assert pgpy_verifies(armored), rationale
    # the text shown to a reviewer must equal the text the reference hashes
    shown = rfc_dash_unescape(rfc_frame_normalize(extract_cleartext(armored)))
    assert msg.message == shown
    assert hashdata_matches_reference(armored), rationale


def test_crlf_fixture_roundtrip_and_verify():
    # the shortest saved sample exercising the CRLF frame boundary
    path = os.path.join('tests', 'testdata', 'messages',
                        'cleartext.crlf.signed.asc')
    with open(path, 'rb') as fh:
        armored = fh.read().decode('ascii')
    assert '\r\n' in armored
    msg = PGPMessage.from_blob(armored)
    assert msg.message == 'crlf frame'
    assert pgpy_verifies(armored)
    # export, re-import and verify again: the normalized form is stable
    reloaded = PGPMessage.from_blob(str(msg))
    assert reloaded.message == 'crlf frame'
    assert pgpy_verifies(str(msg))


def test_export_then_reimport_is_stable(corpus):
    msg = PGPMessage.from_blob(corpus['base'].replace('\n', '\r\n'))
    exported = str(msg)
    assert '\r' not in exported  # PGPy always emits a canonical LF frame
    reimported = PGPMessage.from_blob(exported)
    assert reimported.message == msg.message == 'Hello World'
    assert pgpy_verifies(exported)


# ---------------------------------------------------------------------------
# Substantive content changes: verification must fail (or the armor must be
# rejected). None of these are line-ending or dash-escaping normalizations.
# ---------------------------------------------------------------------------
MUTATIONS = [
    ('trailing_space', 'base', lambda a: a.replace('Hello World\n', 'Hello World \n'),
     'trailing space is signed content (RFC 4880 7.1 warns it is significant)'),
    ('trailing_tab', 'base', lambda a: a.replace('Hello World\n', 'Hello World\t\n'),
     'trailing tab is signed content'),
    ('leading_space', 'base', lambda a: a.replace('Hello World\n', ' Hello World\n'),
     'leading whitespace changes the line'),
    ('interior_tab', 'base', lambda a: a.replace('Hello World', 'Hello\tWorld'),
     'interior characters are preserved verbatim'),
    ('changed_letter', 'base', lambda a: a.replace('Hello World', 'Hello Wxrld'),
     'visible content change'),
    ('extra_dash_escape_space', 'dash',
     lambda a: a.replace('- -danger', '- - -danger'),
     'the added escape decodes to a literal "- " prefix in the signed line'),
    ('tampered_dash_line', 'dash', lambda a: a.replace('- -danger', '- -dang3r'),
     'content change inside a dash-escaped line'),
    ('blank_line_inserted_middle', 'blanks',
     lambda a: a.replace('a\n\nb', 'a\n\n\nb'),
     'an extra interior blank line changes the document'),
    ('blank_line_inserted_before_sig', 'blanks',
     lambda a: a.replace(SIG_SEP, '\n' + SIG_SEP, 1),
     'an extra trailing blank line changes the signed document'),
    ('final_newline_added', 'simple',
     lambda a: a.replace('abc\n-----', 'abc\n\n-----'),
     'the framing newline is excluded; a second one is signed content'),
    ('tampered_decoy_line', 'decoy', lambda a: a.replace('\nfake\n', '\nFAKE\n'),
     'body text that merely looks like armor is still signed content'),
]


@pytest.mark.parametrize('name,key,mutate,rationale', MUTATIONS,
                         ids=[c[0] for c in MUTATIONS])
def test_substantive_changes_fail(corpus, name, key, mutate, rationale):
    armored = mutate(corpus[key])
    try:
        PGPMessage.from_blob(armored)
    except PGPError:
        # rejecting a frame we cannot parse is also an acceptable hard failure
        return
    assert not pgpy_verifies(armored), rationale


def test_dropped_framing_newline_is_rejected(corpus):
    # removing the mandatory line ending before the signature block yields a
    # frame that cannot be parsed at all, rather than a silently truncated doc
    broken = corpus['simple'].replace('abc\n-----BEGIN', 'abc-----BEGIN')
    with pytest.raises(ValueError):
        PGPMessage.from_blob(broken)


def test_bare_cr_is_not_a_line_ending(corpus):
    # a bare CR that is not part of CRLF is genuine content, not a frame byte
    armored = corpus['base'].replace('Hello World\n-----', 'Hello World\r-----')
    with pytest.raises(ValueError):
        PGPMessage.from_blob(armored)


def test_reference_function_documents_equivalence():
    # locks the independent reference itself: only line endings and the
    # RFC 7.1 dash escape may collapse distinct armors to one digest input
    lf = make_signed_armor('line1\nline2')
    crlf = lf.replace('\n', '\r\n')
    assert rfc_expected_digest(extract_cleartext(lf)) == \
        rfc_expected_digest(extract_cleartext(crlf))
    spaced = lf.replace('line1\n', 'line1 \n')
    assert rfc_expected_digest(extract_cleartext(lf)) != \
        rfc_expected_digest(extract_cleartext(spaced))


# ---------------------------------------------------------------------------
# Optional GnuPG cross-check: confirms PGPy agrees with the reference
# implementation's canonicalization on the same wire bytes. Skipped when no
# gpg binary is available (e.g. CI images without GnuPG).
# ---------------------------------------------------------------------------
GPG_BIN = shutil.which('gpg')


def gpg_verifies(armored, home):
    with tempfile.NamedTemporaryFile('w', suffix='.asc', delete=False,
                                     newline='') as handle:
        handle.write(armored)
        path = handle.name
    try:
        proc = subprocess.run(
            [GPG_BIN, '--homedir', home, '--status-fd', '1', '--verify', path],
            capture_output=True, text=True)
    finally:
        os.unlink(path)
    output = proc.stdout + proc.stderr
    if '[GNUPG:] GOODSIG' in output:
        return True
    if '[GNUPG:] BADSIG' in output:
        return False
    pytest.skip('gpg could not evaluate the armor: ' + output.strip()[:200])


@pytest.mark.skipif(GPG_BIN is None, reason='gpg binary not installed')
def test_pgpy_matches_gnupg_on_equivalent_frames(corpus, tmp_path):
    home = tmp_path / 'gnupghome'
    home.mkdir(mode=0o700)
    pubkey = os.path.join(KEY, 'rsa.1.pub.asc')
    # gpg may return non-zero on a successful import because of trust-db warnings
    subprocess.run([GPG_BIN, '--homedir', str(home), '--batch', '--import',
                    pubkey], capture_output=True)

    equivalent_armors = [mutate(corpus[key]) for _, key, mutate, _ in EQUIVALENT]
    for armored in equivalent_armors:
        assert pgpy_verifies(armored)
        assert gpg_verifies(armored, str(home))

    # GnuPG additionally tolerates trailing whitespace as a local, non-RFC
    # leniency; PGPy must keep rejecting it, so the reference (and PGPy) treat
    # it as a substantive change even where gpg happens to accept it.
    soft = corpus['base'].replace('Hello World\n', 'Hello World \n')
    assert not pgpy_verifies(soft)
    assert gpg_verifies(soft, str(home)) is True
