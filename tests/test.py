from Crypto.Cipher import AES 
import Sandra as sandra
import unittest

class TestSandra(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('./taylor_txt/taylor_swift_1KB.txt', 'rb') as f:
            cls.taylor_swift_1KB = f.read()
        cls.iv   = bytes.fromhex('fffffe00000000000000000000000000')
        cls.key  = bytes.fromhex('00000000000000000000000000000000')
    def test_cfb_enc_16(self):
        encryptor = AES.new(
            TestSandra.key, 
            AES.MODE_CFB, 
            TestSandra.iv, 
            segment_size=16)
        enc_dec_sandra = sandra.AES(
            TestSandra.key, 
            sandra.MODE_CFB, 
            TestSandra.iv, 
            segment_size=16)
        ciphertext = encryptor.encrypt(TestSandra.taylor_swift_1KB)
        ciphertext_2 = enc_dec_sandra.encrypt(TestSandra.taylor_swift_1KB)
        self.assertEqual(len(ciphertext), len(ciphertext_2))
        self.assertEqual(ciphertext, ciphertext_2)
        self.assertEqual(ciphertext.hex(), ciphertext_2.hex())
    def test_cfb_dec_16(self):
        encryptor = AES.new(
            TestSandra.key, 
            AES.MODE_CFB, 
            TestSandra.iv, 
            segment_size=16)
        decryptor = AES.new(
            TestSandra.key, 
            AES.MODE_CFB, 
            TestSandra.iv, 
            segment_size=16)
        enc_dec_sandra = sandra.AES(
            TestSandra.key, 
            sandra.MODE_CFB, 
            TestSandra.iv, 
            segment_size=16)
        ciphertext = encryptor.encrypt(TestSandra.taylor_swift_1KB)
        ciphertext_2 = enc_dec_sandra.encrypt(TestSandra.taylor_swift_1KB)
        self.assertEqual(len(ciphertext), len(ciphertext_2))
        self.assertEqual(ciphertext, ciphertext_2)
        self.assertEqual(ciphertext.hex(), ciphertext_2.hex())
        self.assertEqual(
            decryptor.decrypt(ciphertext),
            enc_dec_sandra.decrypt(ciphertext_2))
    def test_cfb_enc_32(self):
        encryptor = AES.new(
            TestSandra.key, 
            AES.MODE_CFB, 
            TestSandra.iv, 
            segment_size=32)
        enc_dec_sandra = sandra.AES(
            TestSandra.key, 
            sandra.MODE_CFB, 
            TestSandra.iv, segment_size=32)
        ciphertext = encryptor.encrypt(TestSandra.taylor_swift_1KB)
        ciphertext_2 = enc_dec_sandra.encrypt(TestSandra.taylor_swift_1KB)
        self.assertEqual(len(ciphertext), len(ciphertext_2))
        self.assertEqual(ciphertext, ciphertext_2)
        self.assertEqual(ciphertext.hex(), ciphertext_2.hex())
    def test_cfb_dec_32(self):
        iv   = bytes.fromhex('fffffe00000000000000000000000000')
        key  = bytes.fromhex('00000000000000000000000000000000')
        encryptor = AES.new(key, AES.MODE_CFB, iv, segment_size=32)
        decryptor = AES.new(key, AES.MODE_CFB, iv, segment_size=32)
        enc_dec_sandra = sandra.AES(key, sandra.MODE_CFB, iv, segment_size=32)
        ciphertext = encryptor.encrypt(TestSandra.taylor_swift_1KB)
        ciphertext_2 = enc_dec_sandra.encrypt(TestSandra.taylor_swift_1KB)
        self.assertEqual(len(ciphertext), len(ciphertext_2))
        self.assertEqual(ciphertext, ciphertext_2)
        self.assertEqual(ciphertext.hex(), ciphertext_2.hex())
        self.assertEqual(
            decryptor.decrypt(ciphertext),
            enc_dec_sandra.decrypt(ciphertext_2))
    def test_openpgp_enc(self):
        encryptor = AES.new(TestSandra.key, AES.MODE_OPENPGP, TestSandra.iv)
        enc_dec_sandra = sandra.AES(TestSandra.key, sandra.MODE_OPENPGP, TestSandra.iv)
        ct = encryptor.encrypt(TestSandra.taylor_swift_1KB)
        eiv, ct = ct[:18], ct[18:]
        decryptor = AES.new(TestSandra.key, AES.MODE_OPENPGP, eiv)
        ct2 = enc_dec_sandra.encrypt(TestSandra.taylor_swift_1KB)
        eiv2, ct2 = ct2[:18], ct2[18:]
        self.assertEqual(len(eiv), len(eiv2))
        self.assertEqual(eiv, eiv2)
        self.assertEqual(ct.hex(), ct2.hex())
        self.assertEqual(ct.hex(), ct2.hex())
        self.assertEqual(
            decryptor.decrypt(ct),
            enc_dec_sandra.decrypt(ct2))



unittest.main()