from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_OAEP


class RSA:
    def __init__(self, keysize):
        if keysize < 1024 or keysize % 2 != 0 :
            raise ValueError(f"Key Size must be multiples of 2 and >= 1024")
        self._keysize = keysize
        self._key = rsa.generate(keysize)
        self._private_key = self._key.export_key('PEM')
        self._public_key = self._key.publickey().exportKey('PEM')

    def encrypt(self, plaintext):
        encryptor = PKCS1_OAEP.new(rsa.importKey(self._public_key))
        maxBytes = int(self._keysize/8 -2 - 2*160/8)
        ciphertext = bytes()
        for i in range(len(plaintext) // maxBytes):
            ciphertext += encryptor.encrypt(
                plaintext[i*maxBytes:(i+1)*maxBytes]
                )
        rem = len(plaintext) % maxBytes
        if rem != 0:
            ciphertext += encryptor.encrypt(plaintext[-rem:])
        return ciphertext
    def decrypt(self, ciphertext):
        decryptor = PKCS1_OAEP.new(rsa.importKey(self._private_key))
        keysizeInBytes = self._keysize // 8
        plaintext = bytes()
        for i in range(len(ciphertext) // keysizeInBytes):
            plaintext += decryptor.decrypt(ciphertext[i*keysizeInBytes:(i+1)*keysizeInBytes])
        return plaintext
