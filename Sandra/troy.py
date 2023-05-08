from Crypto.PublicKey import RSA as rsa
import rsa as rsa2
from Crypto.Cipher import PKCS1_OAEP
import warnings
from .helpers import is_power_of_2

RSA_ENGINE_RAW = 64
RSA_ENGINE_DOME = 65
class RSA:
    """
    A class Wrapper used to encrypt large chunks of data with RSA

    ...

    Attributes
    ----------
    keysize : int
        must be a power of 2
    engine : int flag
        The cipher engine used for Encyption either PyCryptodome or Raw RSA

    Methods
    -------
    encrypt(plaintext)
        takes a bytes object of any size and returns ciphertext
    decrypt(ciphertext)
        takes a bytes object of any size and returns plaintext
    """
    def __init__(self, keysize, engine=RSA_ENGINE_RAW):
        if not is_power_of_2(keysize):
            raise ValueError(f"Key Size must be a power of 2. {keysize} given.")
        self._keysize = keysize
        if engine == RSA_ENGINE_RAW:
            self._engine = engine
            self._public_key, self._private_key = rsa2.newkeys(keysize)
        elif engine == RSA_ENGINE_DOME:
            if keysize < 1024:
                raise ValueError(
                    f"When Using RSA_ENGINE_DOME, Key Size must be > 1024. {keysize} given."
                    )
            self._engine = engine
            self._key = rsa.generate(keysize)
            self._private_key = self._key.export_key('PEM')
            self._public_key = self._key.publickey().exportKey('PEM')
        else:
            raise ValueError(f"Invalid Encryption Engine. Use Either RSA_ENGINE_RAW or RSA_ENGINE_DOME")

    def encrypt(self, plaintext):
        if self._engine == RSA_ENGINE_RAW:
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
        if self._engine == RSA_ENGINE_RAW:
            decryptor = lambda d : rsa2.decrypt(d, self._private_key)
        else:
            decryptor_engine = PKCS1_OAEP.new(rsa.importKey(self._private_key))
            decryptor = lambda d : decryptor_engine.decrypt(d)
        keysizeInBytes = self._keysize // 8
        plaintext = bytearray()
        for i in range(len(ciphertext) // keysizeInBytes):
            plaintext += decryptor(ciphertext[i*keysizeInBytes:(i+1)*keysizeInBytes])
        return bytes(plaintext)
