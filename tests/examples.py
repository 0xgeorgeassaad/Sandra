import Sandra

print(Sandra.__version__)

# RSA 
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
enc_dec_rsa = Sandra.RSA(1024)
ciphertext = enc_dec_rsa.encrypt(file_data[0])
print(len(ciphertext))
plaintext = enc_dec_rsa.decrypt(ciphertext)
print(plaintext == file_data[0])
Sandra.write_data(
    file_names, # name of file to be written
    [plaintext], # data to be written, must be same length as file_names
    path='./taylor_txt_ed' # path to write data to
)



#AES CFB
iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
enc_dec_cfb = Sandra.AES(key, Sandra.MODE_CFB, iv, segment_size=16)
ciphertext = enc_dec_cfb.encrypt(file_data[0])
print(len(ciphertext))
plaintext = enc_dec_cfb.decrypt(ciphertext)
print(plaintext == file_data[0])
Sandra.write_data(
    file_names, # name of file to be written
    [plaintext], # data to be written, must be same length as file_names
    path='./taylor_txt_ed' # path to write data to
)


# OpenPGP
iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
enc_dec_pgp = Sandra.AES(key, Sandra.MODE_OPENPGP, iv)
ciphertext = enc_dec_pgp.encrypt(file_data[0])
eiv, ciphertext = ciphertext[:18], ciphertext[18:]
print(len(ciphertext))
plaintext = enc_dec_pgp.decrypt(ciphertext)
print(plaintext == file_data[0])
Sandra.write_data(
    file_names, # name of file to be written
    [plaintext], # data to be written, must be same length as file_names
    path='./taylor_txt_ed' # path to write data to
)