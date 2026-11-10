""" test handling of unrecognized (Opaque) signature subpackets

RFC 4880 5.2.3.1: if a subpacket in the hashed subpacket area is encountered
that is not understood, but its critical bit is set, the implementation MUST
consider the signature invalid. Non-critical unrecognized subpackets, and any
subpacket in the unhashed area, MUST be ignored. In all cases the original
subpacket type id, critical bit, payload and area placement must be preserved
through parsing and re-export.
"""
import warnings

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPSignature

from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import SecurityIssues
from pgpy.constants import SignatureType

from pgpy.packet import Packet
from pgpy.packet.subpackets.signature import KeyFlags as KeyFlagsSubPacket
from pgpy.packet.subpackets.types import Opaque as OpaqueSubPacket


KEYPATH = 'tests/testdata/keys/rsa.1.sec.asc'
SUBJECT = "this subject is signed with future OpenPGP extensions"
UNKNOWN_TYPEID = 0x77


def _opaque_subpacket(typeid, critical, payload=b'future-extension-data'):
    sp = OpaqueSubPacket()
    sp.header.typeid = typeid
    sp.header.critical = critical
    sp.payload = payload
    sp.update_hlen()
    return sp


def _sign_with_subpackets(key, subject, subpackets):
    # subpackets are added before the cryptographic signature is computed, so
    # hashed-area subpackets are covered by the signature digest
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        sig = PGPSignature.new(SignatureType.BinaryDocument,
                               key.key_algorithm,
                               HashAlgorithm.SHA256,
                               key.fingerprint.keyid)
        for hashed, sp in subpackets:
            storage_key = ('h_' if hashed else '') + sp.__class__.__name__
            sig._signature.subpackets[storage_key] = sp
        return key._sign(subject, sig)


@pytest.fixture(scope='module')
def seckey():
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return PGPKey.from_file(KEYPATH)[0]


@pytest.fixture(scope='module')
def pubkey(seckey):
    return seckey.pubkey


def _issues(sv):
    assert len(sv) == 1
    return sv._subjects[0].issues


class TestOpaqueSubPacketPreservation(object):
    def test_parse_preserves_type_flag_payload_and_area(self, seckey):
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, True, b'\x01\x02\x03\x04')),
            (False, _opaque_subpacket(0x42, False, b'advisory only')),
        ])
        raw = bytes(sig)

        parsed = PGPSignature.from_blob(raw)
        subpackets = parsed._signature.subpackets

        hashed_opaque = [sp for sp in subpackets.hashed if isinstance(sp, OpaqueSubPacket)]
        unhashed_opaque = [sp for sp in subpackets.unhashed if isinstance(sp, OpaqueSubPacket)]

        assert len(hashed_opaque) == 1
        assert hashed_opaque[0].header.typeid == UNKNOWN_TYPEID
        assert hashed_opaque[0].header.critical is True
        assert bytes(hashed_opaque[0].payload) == b'\x01\x02\x03\x04'

        assert len(unhashed_opaque) == 1
        assert unhashed_opaque[0].header.typeid == 0x42
        assert unhashed_opaque[0].header.critical is False
        assert bytes(unhashed_opaque[0].payload) == b'advisory only'

        # re-export must be byte-identical: nothing is normalized or dropped
        assert bytes(parsed) == raw

    def test_roundtrip_through_packet_layer(self, seckey):
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, True)),
        ])
        pkt = Packet(bytearray(bytes(sig)))
        assert bytes(pkt) == bytes(sig)
        assert any(isinstance(sp, OpaqueSubPacket) and sp.header.critical
                   for sp in pkt.subpackets.hashed)

    def test_same_typeid_different_critical_flags_distinguished(self, seckey):
        non_critical = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(0x42, False)),
        ])
        critical = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(0x42, True)),
        ])

        nc_pkt = Packet(bytearray(bytes(non_critical)))
        c_pkt = Packet(bytearray(bytes(critical)))
        nc_sp = next(sp for sp in nc_pkt.subpackets.hashed if isinstance(sp, OpaqueSubPacket))
        c_sp = next(sp for sp in c_pkt.subpackets.hashed if isinstance(sp, OpaqueSubPacket))

        assert nc_sp.header.typeid == c_sp.header.typeid == 0x42
        assert nc_sp.header.critical is False
        assert c_sp.header.critical is True


class TestUnknownCriticalSubPacketVerification(object):
    def test_non_critical_hashed_unknown_is_accepted(self, seckey, pubkey):
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, False)),
        ])
        sv = pubkey.verify(SUBJECT, sig)
        assert sv
        assert _issues(sv) == SecurityIssues.OK

    def test_non_critical_unhashed_unknown_is_accepted(self, seckey, pubkey):
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (False, _opaque_subpacket(UNKNOWN_TYPEID, False)),
        ])
        sv = pubkey.verify(SUBJECT, sig)
        assert sv
        assert _issues(sv) == SecurityIssues.OK

    def test_critical_unhashed_unknown_is_ignored(self, seckey, pubkey):
        # the unhashed area is advisory: even a critical unknown subpacket there
        # does not participate in signature interpretation
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (False, _opaque_subpacket(UNKNOWN_TYPEID, True)),
        ])
        sv = pubkey.verify(SUBJECT, sig)
        assert sv
        assert _issues(sv) == SecurityIssues.OK
        assert sig.unknown_critical_subpackets == []

    def test_critical_hashed_unknown_is_rejected(self, seckey, pubkey):
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, True)),
        ])
        sv = pubkey.verify(SUBJECT, sig)

        assert not sv
        # the cryptographic signature itself is still valid: the rejection is
        # solely due to the unrecognized critical extension, not a broken digest
        assert _issues(sv) == SecurityIssues.UnknownCriticalSubpacket
        assert len(sig.unknown_critical_subpackets) == 1

    def test_critical_hashed_unknown_combined_with_broken_digest(self, seckey, pubkey):
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, True)),
        ])

        # tamper with the signature MPI after signing so the digest no longer verifies
        raw = bytearray(bytes(sig))
        raw[-1] ^= 0x01
        tampered = PGPSignature.from_blob(bytes(raw))

        sv = pubkey.verify(SUBJECT, tampered)
        assert not sv
        # both failure causes are retained instead of one masking the other
        assert _issues(sv) == (SecurityIssues.UnknownCriticalSubpacket | SecurityIssues.WrongSig)

    def test_known_critical_subpacket_is_not_opaque(self, seckey, pubkey):
        critical_known = KeyFlagsSubPacket()
        critical_known.header.critical = True
        critical_known.flags = [KeyFlags.Sign]
        critical_known.update_hlen()

        # a recognized subpacket remains typed even with its critical bit set
        sig = _sign_with_subpackets(seckey, SUBJECT, [
            (True, critical_known),
        ])

        pkt = Packet(bytearray(bytes(sig)))
        known = next(sp for sp in pkt.subpackets.hashed if sp.header.typeid == 0x1B)
        assert isinstance(known, KeyFlagsSubPacket)
        assert not isinstance(known, OpaqueSubPacket)
        assert known.header.critical is True

        sv = pubkey.verify(SUBJECT, sig)
        assert sv
        assert _issues(sv) == SecurityIssues.OK


class TestMultipleSignatures(object):
    def test_mixed_verification_results_keep_per_signature_causes(self, seckey, pubkey):
        good = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, False)),
        ])
        bad = _sign_with_subpackets(seckey, SUBJECT, [
            (True, _opaque_subpacket(UNKNOWN_TYPEID, True)),
        ])

        message = PGPMessage.new(SUBJECT)
        message |= good
        message |= bad

        sv = pubkey.verify(message)
        assert not sv
        assert len(sv) == 2

        results = {s.signature: s.issues for s in sv._subjects}
        assert results[good] == SecurityIssues.OK
        assert results[bad] == SecurityIssues.UnknownCriticalSubpacket

        good_set = {s.signature for s in sv.good_signatures}
        bad_set = {s.signature for s in sv.bad_signatures}
        assert good in good_set
        assert bad in bad_set
