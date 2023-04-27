from Crypto.Cipher import AES as aes
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
import warnings


MODE_CFB = 1
MODE_OPENPGP_STANDALONE = 2 # Deprecated use MODE_OPENPGP
MODE_OPENPGP = 3

class AES:
    def __init__(self, key, mode, iv, segment_size=8):
        if segment_size %8 != 0:
            raise ValueError(f"Segment Size must be multiples of a byte(octet) for all Modes.")
        if len(key) != aes.block_size:
            raise ValueError(f"Length of Key must be {aes.block_size} bytes for all Modes.")
        if len(iv) != aes.block_size:
            raise ValueError(f"Length of IV must be {aes.block_size} bytes for all Modes.")
        if mode == MODE_OPENPGP_STANDALONE:
            warnings.warn(
                "MODE_OPENPGP_STANDALONE Deprecated use MODE_OPENPGP instead", 
                FutureWarning,
                stacklevel=2)
        self._mode = mode
        self._key = key
        self._iv = iv
        self._eiv = None
        if mode == MODE_OPENPGP or mode == MODE_OPENPGP_STANDALONE:
            self._s = aes.block_size
        else:
            self._s = segment_size // 8 # no. of octets instead of bits

    def encrypt(self, plaintext):
        # preprocess
        if self._mode == MODE_CFB: 
            ciphertext = AES._encrypt_CFB(
                plaintext, 
                self._key, 
                self._iv, 
                self._s)
        elif self._mode == MODE_OPENPGP_STANDALONE:
            # Deprecated, Shouldn't be implemented this way
            # http://tools.ietf.org/html/rfc4880 
            random_data = self._iv
            # 1.
            FR = b'\x00' * aes.block_size
            # 2.
            cipher = aes.new(self._key, aes.MODE_ECB)
            FRE = cipher.encrypt(FR)
            # 3.
            ciphertext = strxor(FRE, random_data)
            # 4.
            FR = ciphertext
            # 5.
            FRE = cipher.encrypt(FR)
            # 6.
            ciphertext += strxor(FRE[:2], random_data[-2:])
            self._eiv = ciphertext
            # 7.
            FR = ciphertext[-self._s:]
            # 8. and forward
            for i in range(len(plaintext) // self._s):
                m = plaintext[i*self._s : (i+1)*self._s]
                FRE = cipher.encrypt(FR)
                c = strxor(m, FRE)
                ciphertext += c
                FR = c
            rem = len(plaintext) % self._s
            if rem != 0:
                out = cipher.encrypt(FR)
                ciphertext += strxor(plaintext[-rem:], out[:rem])
        elif self._mode == MODE_OPENPGP:
            self._eiv = AES._encrypt_CFB(
                self._iv + self._iv[-2:], 
                self._key, 
                b'\x00' * aes.block_size, 
                aes.block_size)
            ciphertext = self._eiv
            ciphertext += AES._encrypt_CFB(
                plaintext,
                self._key,
                self._eiv[-aes.block_size:],
                self._s)
        return ciphertext

    def decrypt(self, ciphertext):
        if self._mode == MODE_CFB:
            plaintext = AES._decrypt_CFB(
                ciphertext,
                self._key,
                self._iv,
                self._s)
        elif self._mode == MODE_OPENPGP or self._mode == MODE_OPENPGP_STANDALONE:
            if self._eiv is None:
                raise RuntimeError(f"In OpenPGP mode, encrypt need to be called first.")
            plaintext = AES._decrypt_CFB(
                ciphertext,
                self._key,
                self._eiv[-aes.block_size:],
                self._s)
        return plaintext
    
    @staticmethod
    def _encrypt_CFB(plaintext, key, iv, s):

        cipher = aes.new(key, aes.MODE_ECB)
        x = iv
        ciphertext = bytes()
        for i in range(len(plaintext) // s):
            m = plaintext[i*s : (i+1)*s]
            out = cipher.encrypt(x)
            c = strxor(m, out[:s])
            ciphertext += c
            x = x[s:] + c
        rem = len(plaintext) % s
        if rem != 0:
            out = cipher.encrypt(x)
            ciphertext += strxor(plaintext[-rem:], out[:rem])
        return ciphertext
    
    @staticmethod
    def _decrypt_CFB(ciphertext, key, iv, s):
        cipher = aes.new(key, aes.MODE_ECB)
        x = iv
        plaintext = bytes()
        for i in range(len(ciphertext) // s):
            c = ciphertext[i*s : (i+1)*s]
            out = cipher.encrypt(x)
            m = strxor(c, out[:s])
            plaintext += m
            x = x[s:] + c
        rem = len(ciphertext) % s
        if rem != 0:
            out = cipher.encrypt(x)
            plaintext += strxor(ciphertext[-rem:], out[:rem])
        return plaintext
