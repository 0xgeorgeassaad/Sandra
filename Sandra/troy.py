from Crypto.PublicKey import RSA as rsa
import rsa as rsa2
from Crypto.Cipher import PKCS1_OAEP
import warnings
from .helpers import is_power_of_2
class RSA:
    def __init__(self, keysize):
        if not is_power_of_2(keysize):
            raise ValueError(f"Key Size must be a power of 2")
        self._keysize = keysize
        if keysize >= 1024:
            self._key = rsa.generate(keysize)
            self._private_key = self._key.export_key('PEM')
            self._public_key = self._key.publickey().exportKey('PEM')
        else:
            warnings.warn(
                f"Using {keysize} bit Key Size is not secure, Use at least 1024 bit", 
                stacklevel=2)
            self._public_key, self._private_key = rsa2.newkeys(keysize)

    def encrypt(self, plaintext):
        if self._keysize < 1024:
            encryptor = lambda d : rsa2.encrypt(d, self._public_key)
            maxBytes = int(self._keysize/8 - 11)
        else:
            encryptor_engine = PKCS1_OAEP.new(rsa.importKey(self._public_key))
            encryptor = lambda d : encryptor_engine.encrypt(d)
            maxBytes = int(self._keysize/8 -2 - 2*160/8)
        ciphertext = bytearray()
        for i in range(len(plaintext) // maxBytes):
            ciphertext += encryptor(
                plaintext[i*maxBytes:(i+1)*maxBytes]
                )
        rem = len(plaintext) % maxBytes
        if rem != 0:
            ciphertext += encryptor(plaintext[-rem:])
        return bytes(ciphertext)
    def decrypt(self, ciphertext):
        if self._keysize < 1024:
            decryptor = lambda d : rsa2.decrypt(d, self._private_key)
        else:
            decryptor_engine = PKCS1_OAEP.new(rsa.importKey(self._private_key))
            decryptor = lambda d : decryptor_engine.decrypt(d)
        keysizeInBytes = self._keysize // 8
        plaintext = bytearray()
        for i in range(len(ciphertext) // keysizeInBytes):
            plaintext += decryptor(ciphertext[i*keysizeInBytes:(i+1)*keysizeInBytes])
        return bytes(plaintext)
