""" test the strict key selection entry point of PGPKeyring
"""
import pytest

from datetime import datetime, timezone

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPUID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.errors import PGPAmbiguousKeyError
from pgpy.types import Fingerprint


def _make_key(name, created, email='alice@example.com'):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024, created=created)
    uid = PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    return key


def _make_subkey(primary, created):
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024, created=created)
    primary.add_subkey(subkey, usage={KeyFlags.Sign})
    return subkey


@pytest.fixture(scope='module')
def key_a():
    return _make_key('Alice One', datetime(2020, 1, 1, tzinfo=timezone.utc))


@pytest.fixture(scope='module')
def key_b():
    # same email as key_a, but created later
    return _make_key('Alice Two', datetime(2021, 1, 1, tzinfo=timezone.utc))


@pytest.fixture(scope='module')
def subkey_a(key_a):
    return _make_subkey(key_a, datetime(2020, 6, 1, tzinfo=timezone.utc))


@pytest.fixture(scope='module')
def subkey_b(key_b):
    return _make_subkey(key_b, datetime(2021, 6, 1, tzinfo=timezone.utc))


class TestStrictSelection(object):
    def test_email_ambiguous_regardless_of_load_order(self, key_a, key_b):
        # the loose entry point resolves duplicates by creation time; the strict one must not
        for keys in ([key_a, key_b], [key_b, key_a]):
            keyring = PGPKeyring()
            keyring.load(*keys)

            with pytest.raises(PGPAmbiguousKeyError) as excinfo:
                with keyring.key_strict('alice@example.com'):
                    pass

            assert str(key_a.fingerprint) in str(excinfo.value)
            assert str(key_b.fingerprint) in str(excinfo.value)
            assert 'user id email' in str(excinfo.value)

    def test_loose_entry_point_unchanged(self, key_a, key_b):
        # the pre-existing lenient entry point keeps its creation-time based behavior:
        # it silently picks one of the colliding keys instead of failing
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        with keyring.key('alice@example.com') as key:
            assert key.fingerprint in {key_a.fingerprint, key_b.fingerprint}

    def test_explicit_fingerprint_selects_uniquely(self, key_a, key_b):
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        for ident in (str(key_a.fingerprint),
                      Fingerprint(str(key_a.fingerprint)),
                      key_a.fingerprint.__pretty__()):
            with keyring.key_strict(ident) as key:
                assert key.fingerprint == key_a.fingerprint

    def test_keyid_and_shortid(self, key_a, key_b):
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        with keyring.key_strict(key_a.fingerprint.keyid) as key:
            assert key.fingerprint == key_a.fingerprint

        with keyring.key_strict(key_a.fingerprint.shortid) as key:
            assert key.fingerprint == key_a.fingerprint

    def test_public_private_halves_are_single_candidate(self, key_a):
        keyring = PGPKeyring()
        keyring.load(key_a, key_a.pubkey)

        # both halves of the same key are loaded, but they are one logical candidate
        with keyring.key_strict('alice@example.com') as key:
            assert key.fingerprint == key_a.fingerprint
            assert not key.is_public

        with keyring.key_strict('alice@example.com', keyhalf='public') as key:
            assert key.is_public

        with keyring.key_strict('alice@example.com', keyhalf='private') as key:
            assert not key.is_public

    def test_duplicate_load_still_unique(self, key_a):
        # loading independently parsed copies of the same key must not create ambiguity
        other_copy, _ = PGPKey.from_blob(bytes(key_a))

        keyring = PGPKeyring()
        keyring.load(key_a)
        keyring.load(other_copy)

        with keyring.key_strict('alice@example.com') as key:
            assert key.fingerprint == key_a.fingerprint

    def test_unload_allows_reselection(self, key_a, key_b):
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        with pytest.raises(PGPAmbiguousKeyError):
            with keyring.key_strict('alice@example.com'):
                pass

        with keyring.key(str(key_b.fingerprint)) as key:
            keyring.unload(key)

        # after unloading one of the colliding keys, the remaining one is selected unambiguously
        with keyring.key_strict('alice@example.com') as key:
            assert key.fingerprint == key_a.fingerprint

    def test_subkey_scoped_to_primary(self, key_a, key_b, subkey_a, subkey_b):
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        # a subkey can be selected through its own primary key
        with keyring.key_strict(str(subkey_a.fingerprint), primary=str(key_a.fingerprint)) as key:
            assert key.fingerprint == subkey_a.fingerprint

        # but a subkey must not be selected detached from its owning primary key
        with pytest.raises(KeyError):
            with keyring.key_strict(str(subkey_a.fingerprint), primary=str(key_b.fingerprint)):
                pass

    def test_primary_fingerprint_disambiguates_email(self, key_a, key_b, subkey_a, subkey_b):
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        with keyring.key_strict('alice@example.com', primary=str(key_a.fingerprint)) as key:
            assert key.fingerprint == key_a.fingerprint

    def test_subkey_unique_without_primary_constraint(self, key_a, subkey_a):
        keyring = PGPKeyring()
        keyring.load(key_a)

        with keyring.key_strict(str(subkey_a.fingerprint)) as key:
            assert key.fingerprint == subkey_a.fingerprint

    def test_no_match_raises_keyerror(self, key_a):
        keyring = PGPKeyring()
        keyring.load(key_a)

        with pytest.raises(KeyError):
            with keyring.key_strict('nobody@example.com'):
                pass

    def test_invalid_keyhalf(self, key_a):
        keyring = PGPKeyring()
        keyring.load(key_a)

        with pytest.raises(ValueError):
            with keyring.key_strict('alice@example.com', keyhalf='both'):
                pass

    def test_ambiguous_error_is_safe(self, key_a, key_b):
        keyring = PGPKeyring()
        keyring.load(key_a, key_b)

        with pytest.raises(PGPAmbiguousKeyError) as excinfo:
            with keyring.key_strict('alice@example.com'):
                pass

        err = excinfo.value
        # candidates are exposed as (fingerprint, basis) pairs
        assert {fp for fp, _ in err.candidates} == {str(key_a.fingerprint), str(key_b.fingerprint)}
        # the message lists safe candidate fingerprints and match bases only
        assert str(key_a.fingerprint) in str(err)
        assert str(key_b.fingerprint) in str(err)
        assert 'user id email' in str(err)
        # and never any private key material
        assert 'PRIVATE' not in str(err)
        assert bytes(key_a) not in bytes(str(err), 'latin-1')
