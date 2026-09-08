import base64
import unittest
from identity_linking import decode_subject


def b64(raw, url=True):
    return (base64.urlsafe_b64encode(raw) if url else base64.b64encode(raw)).decode().rstrip('=')


def subject(uid='a'*64, account='account', connector='connector', suffix=b''):
    raw=b'\x0a'+bytes([len(uid)])+uid.encode()+b'\x12'+bytes([len(connector)])+connector.encode()+suffix
    return 'netbird:'+b64(account.encode())+':'+b64(b64(raw,False).encode())


class IdentityTests(unittest.TestCase):
    def test_verified_immutable_subject(self):
        self.assertEqual(decode_subject(subject(),'account','connector'),'a'*64)

    def test_other_authorities_and_malformed_ids(self):
        bad=[subject(account='other'),subject(connector='other'),subject(uid='email@example.com'),subject(uid='A'*64),subject(uid='a'*64,suffix=b'\x12\x05other'),subject()+':tail',subject()+'=', 'netbird:'+b64(b'account')+':'+b64(b'machine-peer-id')]
        for value in bad:
            with self.subTest(value=value),self.assertRaises(ValueError):
                decode_subject(value,'account','connector')

    def test_no_identifier_aliases(self):
        # Nonzero unused base64 bits cannot provide a second identity spelling.
        canonical=subject();last=canonical[-1]
        alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        mutated=canonical[:-1]+alphabet[(alphabet.index(last)+1)%64]
        with self.assertRaises(ValueError):decode_subject(mutated,'account','connector')

if __name__=='__main__':unittest.main()
