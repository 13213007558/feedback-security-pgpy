""" strict verification of signing subkeys against their primary key

These tests exercise the strict entry point that requires a document signature
to be backed by a valid Subkey Binding Signature (0x18) from the primary key and
a Primary Key Binding Signature (0x19) back-signature from the signing subkey.
"""
import copy

import pytest

from pgpy import PGPKey
from pgpy.constants import KeyFlags
from pgpy.constants import SecurityIssues
from pgpy.constants import SignatureType
from pgpy.errors import PGPKeyBindingError
from pgpy.errors import PGPSignatureError


DOCUMENT = b'Origin: example\nSuite: stable\nLabel: strict-verify\n'


def _load(name):
    return PGPKey.from_file('tests/testdata/keys/{:s}.sec.asc'.format(name))[0]


def _binding(key, keyid):
    return next(sig for sig in key.subkeys[keyid].__sig__
                if sig.type == SignatureType.Subkey_Binding)


def _embedded(binding):
    return next(iter(binding._signature.subpackets['EmbeddedSignature']))


def _strip_embedded(binding):
    containers = (binding._signature.subpackets._unhashed_sp,
                  binding._signature.subpackets._hashed_sp)
    for container in containers:
        for key in list(container.keys()):
            if key[0] == 'EmbeddedSignature':
                del container[key]


def _replace_embedded(binding, embedded):
    _strip_embedded(binding)
    binding._signature.subpackets['EmbeddedSignature'] = embedded
    binding._signature.update_hlen()


def _relocated_binding(rsa, dsa, sign_keyid):
    original_embedded = copy.deepcopy(_embedded(_binding(rsa, sign_keyid)))

    foreign_primary = copy.deepcopy(dsa)
    relocated_subkey = copy.deepcopy(rsa.subkeys[sign_keyid])
    foreign_primary._children[sign_keyid] = relocated_subkey
    relocated_subkey._parent = foreign_primary

    binding = foreign_primary.bind(relocated_subkey, usage={KeyFlags.Sign})
    _replace_embedded(binding, original_embedded)

    relocated_subkey._signatures.clear()
    relocated_subkey |= binding
    return foreign_primary


@pytest.fixture(scope='module')
def rsa():
    return _load('rsa.1')


@pytest.fixture(scope='module')
def dsa():
    return _load('dsa.1')


@pytest.fixture(scope='module')
def sign_keyid():
    return '2A834D8E5918E886'


@pytest.fixture(scope='module')
def enc_keyid():
    return 'EEE097A017B979CA'


@pytest.fixture(scope='module')
def dsa_sign_keyid():
    return 'A5DCDC966453140E'


@pytest.fixture(scope='module')
def document_signature(rsa, sign_keyid):
    return rsa.subkeys[sign_keyid].sign(DOCUMENT)


class TestStrictSubkeyBinding:
    def test_positive_binding_verifies(self, rsa, sign_keyid):
        pub = rsa.pubkey
        binding = pub.verify_subkey_binding(pub.subkeys[sign_keyid])
        assert binding.type == SignatureType.Subkey_Binding
        assert KeyFlags.Sign in binding.key_flags

    def test_dsa_positive_binding_verifies(self, dsa, dsa_sign_keyid):
        pub = dsa.pubkey
        binding = pub.verify_subkey_binding(pub.subkeys[dsa_sign_keyid])
        assert binding.type == SignatureType.Subkey_Binding
        assert KeyFlags.Sign in binding.key_flags

    def test_encryption_subkey_not_asked_for_backsignature(self, rsa, enc_keyid):
        pub = rsa.pubkey
        binding = _binding(pub, enc_keyid)
        assert KeyFlags.Sign not in binding.key_flags
        assert 'EmbeddedSignature' not in binding._signature.subpackets
        with pytest.raises(PGPKeyBindingError):
            pub.verify_subkey_binding(pub.subkeys[enc_keyid])

    def test_non_subkey_is_rejected(self, rsa):
        with pytest.raises(TypeError):
            rsa.pubkey.verify_subkey_binding(rsa.pubkey)

    def test_embedded_signature_of_wrong_type_is_rejected(self, rsa, sign_keyid):
        key = copy.deepcopy(rsa)
        binding = _binding(key, sign_keyid)
        embedded = _embedded(binding)
        embedded._sig.sigtype = SignatureType.Subkey_Binding
        binding._signature.update_hlen()

        pub = key.pubkey
        with pytest.raises(PGPKeyBindingError):
            pub.verify_subkey_binding(pub.subkeys[sign_keyid])

    def test_missing_binding_signature_is_rejected(self, rsa, sign_keyid):
        key = copy.deepcopy(rsa)
        key.subkeys[sign_keyid]._signatures.clear()
        pub = key.pubkey
        with pytest.raises(PGPKeyBindingError) as exc_info:
            pub.verify_subkey_binding(pub.subkeys[sign_keyid])
        assert exc_info.value.security_issue is SecurityIssues.SubkeyBindingNotValid

    @pytest.mark.parametrize('tamper', [
        'missing_backsignature',
        'foreign_backsignature',
        'encryption_only_flags',
        'relocated_binding',
    ])
    def test_binding_failures(self, rsa, dsa, sign_keyid, dsa_sign_keyid, tamper):
        key = copy.deepcopy(rsa)
        binding = _binding(key, sign_keyid)

        if tamper == 'missing_backsignature':
            _strip_embedded(binding)

        elif tamper == 'foreign_backsignature':
            _replace_embedded(binding,
                              copy.deepcopy(_embedded(_binding(dsa, dsa_sign_keyid))))

        elif tamper == 'encryption_only_flags':
            key_flags = next(iter(binding._signature.subpackets['h_KeyFlags']))
            key_flags.flags = {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}

        elif tamper == 'relocated_binding':
            key = _relocated_binding(rsa, dsa, sign_keyid)

        pub = key.pubkey
        with pytest.raises(PGPKeyBindingError):
            pub.verify_subkey_binding(pub.subkeys[sign_keyid])


class TestStrictDocumentVerification:
    def test_strict_accepts_valid_subkey_signature(self, rsa, sign_keyid, document_signature):
        pub = rsa.pubkey
        signer = pub.verify_strict(DOCUMENT, document_signature)
        assert signer.fingerprint.keyid == sign_keyid

    def test_strict_accepts_dsa_subkey_signature(self, dsa, dsa_sign_keyid):
        signature = dsa.subkeys[dsa_sign_keyid].sign(DOCUMENT)
        signer = dsa.pubkey.verify_strict(DOCUMENT, signature)
        assert signer.fingerprint.keyid == dsa_sign_keyid

    def test_document_signature_still_verifies_at_low_level_in_every_negative_case(
            self, rsa, dsa, sign_keyid, dsa_sign_keyid, document_signature):
        cases = {
            'missing_backsignature': self._missing_backsignature(rsa, sign_keyid),
            'foreign_backsignature': self._foreign_backsignature(rsa, dsa, sign_keyid, dsa_sign_keyid),
            'encryption_only_flags': self._encryption_only(rsa, sign_keyid),
            'relocated_binding': _relocated_binding(rsa, dsa, sign_keyid),
        }
        for label, key in cases.items():
            result = key.pubkey.verify(DOCUMENT, document_signature)
            assert result, 'low-level document verification must still pass for {:s}'.format(label)

    def test_strict_rejects_all_binding_failures(
            self, rsa, dsa, sign_keyid, dsa_sign_keyid, document_signature):
        cases = {
            'missing_backsignature': self._missing_backsignature(rsa, sign_keyid),
            'foreign_backsignature': self._foreign_backsignature(rsa, dsa, sign_keyid, dsa_sign_keyid),
            'encryption_only_flags': self._encryption_only(rsa, sign_keyid),
            'relocated_binding': _relocated_binding(rsa, dsa, sign_keyid),
        }
        for label, key in cases.items():
            with pytest.raises(PGPKeyBindingError):
                key.pubkey.verify_strict(DOCUMENT, document_signature)

    def test_bad_document_signature_is_distinct_from_binding_failure(
            self, rsa, document_signature):
        with pytest.raises(PGPSignatureError):
            rsa.pubkey.verify_strict(DOCUMENT + b'tampered\n', document_signature)

    def test_unknown_signer_is_a_binding_failure(self, dsa, document_signature):
        with pytest.raises(PGPKeyBindingError):
            dsa.pubkey.verify_strict(DOCUMENT, document_signature)

    def test_type_errors(self, rsa, document_signature):
        pub = rsa.pubkey
        with pytest.raises(TypeError):
            pub.verify_strict(1234, document_signature)
        with pytest.raises(TypeError):
            pub.verify_strict(DOCUMENT, None)

    @staticmethod
    def _missing_backsignature(rsa, sign_keyid):
        key = copy.deepcopy(rsa)
        _strip_embedded(_binding(key, sign_keyid))
        return key

    @staticmethod
    def _foreign_backsignature(rsa, dsa, sign_keyid, dsa_sign_keyid):
        key = copy.deepcopy(rsa)
        _replace_embedded(_binding(key, sign_keyid),
                          copy.deepcopy(_embedded(_binding(dsa, dsa_sign_keyid))))
        return key

    @staticmethod
    def _encryption_only(rsa, sign_keyid):
        key = copy.deepcopy(rsa)
        binding = _binding(key, sign_keyid)
        key_flags = next(iter(binding._signature.subpackets['h_KeyFlags']))
        key_flags.flags = {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
        return key
