# Requirements:
# apt install python3 python3-pip
# pip3 install cryptography==2.8 pycrypto

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()

def hkdf(inp, length):
    # use HKDF on an input to derive a key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)

class Bob(object):
    def __init__(self):
    #X25519PrivateKey ; this is the elliptic curve 
    #from which we get three keys 

        self.IKb = X25519PrivateKey.generate()
        self.SPKb = X25519PrivateKey.generate()
        self.OPKb = X25519PrivateKey.generate()

    def x3dh(self, alice):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        # first Diffie-Hellman key exchange using his Signed Prekey private key and Alice's long term Identity Key public key 
        dh1 = self.SPKb.exchange(alice.IKa.public_key())
        #Bob computes the second Diffie-Hellman key exchange using his Identity Key private key and Alice's ephemeral key 
        dh2 = self.IKb.exchange(alice.EKa.public_key())
        #Bob computes the third Diffie-Hellman key exchange using his Signed Prekey private key and Alice's ephemeral key 
        dh3 = self.SPKb.exchange(alice.EKa.public_key())
        #Bob computes the fourth Diffie-Hellman key exchange using his One time Pre key private key and Alice's ephemeral key 
        dh4 = self.OPKb.exchange(alice.EKa.public_key())
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key:', b64(self.sk))


class Alice(object):
    def __init__(self):
        # generate Alice's keys
        self.IKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()

    def x3dh(self, bob):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.IKa.exchange(bob.SPKb.public_key())
        dh2 = self.EKa.exchange(bob.IKb.public_key())
        dh3 = self.EKa.exchange(bob.SPKb.public_key())
        dh4 = self.EKa.exchange(bob.OPKb.public_key())
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key:', b64(self.sk))


alice = Alice()
bob = Bob()
alice.x3dh(bob)

# Bob comes online and performs an X3DH using Alice's public keys
bob.x3dh(alice)