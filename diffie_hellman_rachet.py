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

def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]

class SymmRatchet(object):
    #constructer of a class 
    #'self' is reference to the current instance of class
    #'key' This is a parameter passed to the constructor. 
    def __init__(self, key):
        self.state = key
    #memebr function 
    #takes an optional input parameter'inp' , with default value b''
    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        #IV=initializing vector 
        #output = hkdf(self.state + inp, 80): This line seems to be invoking a 
        #function named hkdf with two parameters: the concatenation of the current 
        #state (self.state) and the input (inp), and the length of 80 bytes. 
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv

class Bob(object):
    def __init__(self):
        self.DHratchet = X25519PrivateKey.generate()

    def dh_ratchet(self, alice_public):
        dh_recv = self.DHratchet.exchange(alice_public)
        shared_recv = dh_recv
        self.recv_ratchet = SymmRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_public)
        shared_send = dh_send
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def send(self, alice, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        # send ciphertext and current DH public key
        alice.recv(cipher, self.DHratchet.public_key())

    def recv(self, cipher, alice_public_key):
        # receive Alice's new public key and use it to perform a DH
        self.dh_ratchet(alice_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message:', msg)
    

class Alice(object):
    def __init__(self):
        # Initialize Alice's DH ratchet
        self.DHratchet = X25519PrivateKey.generate()

    def dh_ratchet(self, bob_public):
        if self.DHratchet is not None:
            dh_recv = self.DHratchet.exchange(bob_public)
            shared_recv = dh_recv
            self.recv_ratchet = SymmRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(bob_public)
        shared_send = dh_send
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))

    def send(self, bob, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        bob.recv(cipher, self.DHratchet.public_key())

    def recv(self, cipher, bob_public_key):
        # receive Bob's new public key and use it to perform a DH
        self.dh_ratchet(bob_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Alice]\tDecrypted message:', msg)

alice = Alice()
bob = Bob()

bob_public_key = bob.DHratchet.public_key()
alice_public_key = alice.DHratchet.public_key()

alice.dh_ratchet(bob_public_key)
bob.dh_ratchet(alice_public_key)

alice.send(bob, b'Hello Bob!')
bob.send(alice, b'Hello to you too, Alice!')