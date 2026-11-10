""" errors.py
"""

__all__ = ('PGPError',
           'PGPAmbiguousKeyError',
           'PGPEncryptionError',
           'PGPDecryptionError',
           'PGPIncompatibleECPointFormatError',
           'PGPOpenSSLCipherNotSupportedError',
           'PGPInsecureCipherError',
           'WontImplementError',)


class PGPError(Exception):
    """Raised as a general error in PGPy"""
    pass


class PGPAmbiguousKeyError(PGPError):
    """
    Raised when a strict key selection matches more than one distinct key and therefore cannot be
    resolved unambiguously.

    The string representation only ever contains key fingerprints and the reasons they matched;
    it never contains any key material.
    """
    def __init__(self, identifier, candidates):
        """
        :param identifier: The identifier that produced an ambiguous selection.
        :param candidates: An iterable of ``(fingerprint, basis)`` tuples describing each distinct
                           candidate key and why it matched.
        """
        self.identifier = identifier
        self.candidates = [(str(fingerprint), str(basis)) for fingerprint, basis in candidates]
        matched = ', '.join('{fp:s} (matched by: {basis:s})'.format(fp=fp, basis=basis)
                            for fp, basis in self.candidates)
        super(PGPAmbiguousKeyError, self).__init__(
            "Ambiguous key selection: {ident!r} matched {count:d} distinct keys: {matched:s}. "
            "Disambiguate with a full fingerprint, the keyhalf, or the primary key fingerprint."
            .format(ident=identifier, count=len(self.candidates), matched=matched))


class PGPEncryptionError(Exception):
    """Raised when encryption fails"""
    pass


class PGPDecryptionError(Exception):
    """Raised when decryption fails"""
    pass


class PGPIncompatibleECPointFormatError(Exception):
    """Raised when the point format is incompatible with the elliptic curve"""
    pass


class PGPOpenSSLCipherNotSupportedError(Exception):
    """Raised when OpenSSL does not support the requested cipher"""
    pass


class PGPInsecureCipherError(Exception):
    """Raised when a cipher known to be insecure is attempted to be used to encrypt data"""
    pass


class WontImplementError(NotImplementedError):
    """Raised when something that is not implemented, will not be implemented"""
    pass
