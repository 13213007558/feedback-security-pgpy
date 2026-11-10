"""Ordering guarantee for integrity-protected (tag 18) decryption.

``IntegrityProtectedSKEDataV1.decrypt`` must complete its Modification
Detection Code (MDC) and OpenPGP prefix checks *before* any of the
decrypted plaintext is handed to the packet layer.  In particular, a
message that fails those checks must never reach:

* ``PGPMessage.parse``, which turns plaintext bytes into a ``PGPMessage``,
* ``CompressedData.parse`` / ``CompressionAlgorithm.decompress``, the
  decompression entry point, or
* ``LiteralData.parse``, the literal data packet parser.

The negative samples below are all derived from genuinely encrypted,
locally generated messages (or local test keys); they are not unrelated
random byte strings.  Each mutation invalidates an otherwise valid
integrity-protected message in a specific way.

The legacy Symmetrically Encrypted Data packet (tag 9,
``SKEData``) has no MDC, so none of these guarantees apply to it.  The
behavior of that format is documented separately at the end of this
module and must not be conflated with the tag 18 guarantees.
"""
import warnings
from unittest import mock

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy.constants import CompressionAlgorithm
from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPError
from pgpy.packet.packets import CompressedData
from pgpy.packet.packets import IntegrityProtectedSKEDataV1
from pgpy.packet.packets import LiteralData
from pgpy.packet.packets import SKEData
from pgpy.symenc import _decrypt
from pgpy.symenc import _encrypt

PASSPHRASE = "QwertyUiop"
PLAINTEXT = u"compressed plaintext protected by an MDC"

# every negative case is a small, targeted mutation of one of these
# otherwise valid, integrity-protected messages
CORRUPTIONS = ('bad_mdc', 'truncated', 'misplaced_mdc', 'bad_prefix')

# parser / decompression entry points that must not see failed plaintext
WATCHED_TARGETS = (
    ('message_parse', PGPMessage, 'parse'),
    ('compressed_parse', CompressedData, 'parse'),
    ('literal_parse', LiteralData, 'parse'),
    ('decompress', CompressionAlgorithm, 'decompress'),
)


class ParseWatchpoints(object):
    """Descriptor-safe call counters for the plaintext parsing entry points.

    ``mock.Mock(wraps=...)`` is avoided on purpose: replacing a class
    method with a ``Mock`` breaks the function descriptor protocol, so
    ``obj.parse(packet)`` dispatch inside ``MetaDispatchable`` would no
    longer bind ``self``.  Plain wrapper functions preserve binding.
    """

    def __init__(self):
        self.calls = {name: 0 for name, _, _ in WATCHED_TARGETS}
        self._patches = []
        for name, cls, attr in WATCHED_TARGETS:
            original = getattr(cls, attr)
            counter = self

            def make_wrapper(wrapped, label):
                def wrapper(*args, **kwargs):
                    counter.calls[label] += 1
                    return wrapped(*args, **kwargs)
                return wrapper

            self._patches.append(mock.patch.object(cls, attr, make_wrapper(original, name)))

    def __enter__(self):
        for patch in self._patches:
            patch.start()
        return self

    def __exit__(self, *exc_info):
        for patch in self._patches:
            patch.stop()


def _repack(encrypted_message, plaintext, session_key, sym_alg):
    """Re-encrypt an already parsed plaintext back into a tag 18 message.

    The session key packets of the original, valid message are reused, so
    the result remains a real message encrypted for the same key or
    passphrase rather than an unrelated blob of bytes.
    """
    skedata = IntegrityProtectedSKEDataV1()
    skedata.ct = bytearray(_encrypt(bytes(plaintext), bytes(session_key), sym_alg))
    skedata.update_hlen()

    repacked = PGPMessage()
    for session_key_packet in encrypted_message._sessionkeys:
        repacked |= session_key_packet
    repacked |= skedata
    return repacked


def _corrupt(encrypted_message, session_key, sym_alg, corruption):
    """Return a copy of ``encrypted_message`` carrying one integrity defect."""
    skedata = encrypted_message.message
    assert isinstance(skedata, IntegrityProtectedSKEDataV1)

    plaintext = bytearray(_decrypt(bytes(skedata.ct), bytes(session_key), sym_alg))
    block_size = sym_alg.block_size // 8

    if corruption == 'bad_mdc':
        # flip one byte of the MDC hash: the stored digest no longer
        # matches the SHA-1 computed over the plaintext
        plaintext[-1] ^= 0xFF

    elif corruption == 'truncated':
        # remove the tail, so there is no complete MDC packet at the end
        del plaintext[-5:]

    elif corruption == 'misplaced_mdc':
        # relocate the MDC packet so it is no longer the last packet,
        # which RFC 4880 5.13 requires for tag 18 messages
        mdc_packet = plaintext[-22:]
        del plaintext[-22:]
        plaintext[block_size + 2:block_size + 2] = mdc_packet

    elif corruption == 'bad_prefix':
        # break the duplicated OpenPGP CFB prefix check octet while
        # leaving the MDC packet itself internally consistent
        plaintext[block_size] ^= 0xFF

    else:  # pragma: no cover
        raise ValueError(corruption)

    return _repack(encrypted_message, plaintext, session_key, sym_alg)


@pytest.fixture(scope='module')
def passphrase_message():
    """A valid, compressed, passphrase-encrypted tag 18 message and its key."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        message = PGPMessage.new(PLAINTEXT, compression=CompressionAlgorithm.ZLIB)
        encrypted = message.encrypt(PASSPHRASE)

    skesk = next(iter(encrypted._sessionkeys))
    sym_alg, session_key = skesk.decrypt_sk(PASSPHRASE)
    return encrypted, session_key, sym_alg


@pytest.fixture(scope='module')
def pubkey_message():
    """A valid, compressed message encrypted to a local test RSA key."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        seckey = PGPKey.from_file('tests/testdata/keys/rsa.1.sec.asc')[0]
        message = PGPMessage.new(PLAINTEXT, compression=CompressionAlgorithm.ZLIB)
        encrypted = seckey.pubkey.encrypt(message)

    keyid = next(iter(encrypted.encrypters))
    decrypt_key = seckey._key if keyid == seckey.fingerprint.keyid else seckey.subkeys[keyid]._key
    pkesk = next(pk for pk in encrypted._sessionkeys if pk.encrypter == keyid)
    sym_alg, session_key = pkesk.decrypt_sk(decrypt_key)
    return seckey, encrypted, session_key, sym_alg


def assert_no_plaintext_parsing(watchpoints):
    # nothing may have parsed or decompressed the unauthenticated plaintext
    assert watchpoints.calls == {name: 0 for name, _, _ in WATCHED_TARGETS}


class TestMDCBeforeParsing(object):
    """Tag 18 plaintext is only parsed after every integrity check passes."""

    def test_passphrase_roundtrip_reaches_parsers(self, passphrase_message):
        # positive control: the well-formed compressed message must pass
        # the MDC checks and then actually be decompressed and parsed
        encrypted, _, _ = passphrase_message
        with ParseWatchpoints() as watchpoints:
            decrypted = encrypted.decrypt(PASSPHRASE)

        assert decrypted.message == PLAINTEXT
        assert watchpoints.calls['message_parse'] == 1
        assert watchpoints.calls['compressed_parse'] == 1
        assert watchpoints.calls['decompress'] == 1
        assert watchpoints.calls['literal_parse'] == 1

    @pytest.mark.parametrize('corruption', CORRUPTIONS)
    def test_passphrase_corruption_rejected_before_parsing(self, passphrase_message, corruption):
        encrypted, session_key, sym_alg = passphrase_message
        corrupted = _corrupt(encrypted, session_key, sym_alg, corruption)

        with ParseWatchpoints() as watchpoints:
            decrypted = None
            with pytest.raises(PGPDecryptionError):
                decrypted = corrupted.decrypt(PASSPHRASE)

        # no partial PGPMessage may be returned on failure
        assert decrypted is None
        assert_no_plaintext_parsing(watchpoints)

    def test_pubkey_roundtrip_reaches_parsers(self, pubkey_message):
        # positive control for the public PGPKey.decrypt entry point
        seckey, encrypted, _, _ = pubkey_message
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with ParseWatchpoints() as watchpoints:
                decrypted = seckey.decrypt(encrypted)

        assert decrypted.message == PLAINTEXT
        assert watchpoints.calls['message_parse'] == 1
        assert watchpoints.calls['compressed_parse'] == 1
        assert watchpoints.calls['decompress'] == 1
        assert watchpoints.calls['literal_parse'] == 1

    @pytest.mark.parametrize('corruption', CORRUPTIONS)
    def test_pubkey_corruption_rejected_before_parsing(self, pubkey_message, corruption):
        seckey, encrypted, session_key, sym_alg = pubkey_message
        corrupted = _corrupt(encrypted, session_key, sym_alg, corruption)

        with ParseWatchpoints() as watchpoints:
            decrypted = None
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with pytest.raises(PGPDecryptionError):
                    decrypted = seckey.decrypt(corrupted)

        assert decrypted is None
        assert_no_plaintext_parsing(watchpoints)

    def test_packet_layer_raises_before_any_parsing(self, passphrase_message):
        # directly at the IntegrityProtectedSKEDataV1 boundary, the
        # integrity failure must be raised from decrypt() itself, before
        # the caller could possibly invoke PGPMessage.parse
        encrypted, session_key, sym_alg = passphrase_message
        corrupted = _corrupt(encrypted, session_key, sym_alg, 'bad_mdc')
        skedata = corrupted.message

        with ParseWatchpoints() as watchpoints:
            with pytest.raises(PGPDecryptionError):
                skedata.decrypt(session_key, sym_alg)

        assert_no_plaintext_parsing(watchpoints)


class TestLegacySKEDataHasNoIntegrityGuarantee(object):
    """Document the behavior of the legacy tag 9 packet (no MDC).

    These tests exist to pin down the *current* behavior and to make
    clear that the ordering guarantees above do not extend to formats
    that perform no MDC verification.  They must not be read as a
    security guarantee for tag 9 data.
    """

    def test_legacy_tag9_decrypts_without_mdc_checks(self):
        # a well-formed legacy message is parsed normally; SKEData.decrypt
        # only performs the quick-check prefix comparison and never an MDC
        encrypted = PGPMessage.from_file('tests/testdata/messages/message.literal.nomdc.pass.cast5.asc')
        assert isinstance(encrypted.message, SKEData)
        assert not isinstance(encrypted.message, IntegrityProtectedSKEDataV1)

        with ParseWatchpoints() as watchpoints:
            decrypted = encrypted.decrypt(PASSPHRASE)

        assert decrypted.message.startswith('Lorem ipsum')
        # the plaintext parsers run even though no integrity check exists
        assert watchpoints.calls['message_parse'] == 1
        assert watchpoints.calls['literal_parse'] == 1

    def test_tampered_legacy_tag9_plaintext_is_still_parsed(self):
        # flipping a middle ciphertext byte of a tag 9 packet does not
        # fail any integrity check: SKEData.decrypt returns the garbled
        # plaintext and the literal parser consumes it, producing a
        # PGPMessage with corrupted contents instead of a security error
        encrypted = PGPMessage.from_file('tests/testdata/messages/message.literal.nomdc.pass.cast5.asc')
        encrypted.message.ct[len(encrypted.message.ct) // 2] ^= 0xFF

        with ParseWatchpoints() as watchpoints:
            decrypted = encrypted.decrypt(PASSPHRASE)

        assert isinstance(decrypted, PGPMessage)
        assert watchpoints.calls['message_parse'] == 1
        assert watchpoints.calls['literal_parse'] == 1
        # the content was in fact modified, yet nothing rejected it
        assert decrypted.message != PGPMessage.from_file(
            'tests/testdata/messages/message.literal.nomdc.pass.cast5.asc').decrypt(PASSPHRASE).message

    def test_tampered_legacy_tag9_compressed_fails_late_in_decompression(self):
        # when the legacy plaintext is compressed, corruption is only
        # noticed (if at all) by the decompressor *after* parsing began;
        # the failure is a PGPError wrapping the zlib error, not an
        # integrity-protected PGPDecryptionError
        encrypted = PGPMessage.from_file('tests/testdata/messages/message.nomdc.pass.asc')
        assert isinstance(encrypted.message, SKEData)
        encrypted.message.ct[len(encrypted.message.ct) // 2] ^= 0xFF

        with ParseWatchpoints() as watchpoints:
            with pytest.raises(PGPError):
                encrypted.decrypt(PASSPHRASE)

        # parsing and decompression had already started before the failure,
        # which is precisely what cannot happen with a tag 18 message
        assert watchpoints.calls['message_parse'] == 1
        assert watchpoints.calls['compressed_parse'] == 1
        assert watchpoints.calls['decompress'] == 1
