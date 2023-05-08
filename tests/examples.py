import Sandra

print(Sandra.__version__)



# Performance
file_names, file_data = Sandra.load_data('./taylor_txt')
stats = Sandra.performance_test(
    file_names, 
    file_data, 
    rsa_key_size=256,
    rsa_engine=Sandra.RSA_ENGINE_RAW,
    segment_size=64,  
    verbose=True)

stats = Sandra.performance_test(
    file_names, 
    file_data, 
    rsa_key_size=256,
    rsa_engine=Sandra.RSA_ENGINE_RAW,
    segment_size=16,  
    verbose=True)

""" stats = Sandra.performance_test(
    file_names, 
    file_data, 
    rsa_key_size=2048,
    rsa_engine=Sandra.RSA_ENGINE_DOME,  
    verbose=True) """


# Read and Write a Folder
""" iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')
enc_dec_pgp = Sandra.AES(key, Sandra.MODE_OPENPGP, iv)
plaintext = list()
file_data_padded = Sandra.pad(file_data, Sandra.AES_BLOCK_SIZE)
for i in range(len(file_data)):
  ciphertext = enc_dec_pgp.encrypt(file_data_padded[i])
  eiv, ciphertext = ciphertext[:18], ciphertext[18:]
  plaintext.append(
    Sandra.unpad(
    enc_dec_pgp.decrypt(ciphertext),
    Sandra.AES_BLOCK_SIZE
    )
  )
  print(f"{file_names[i]} Decrypted Successfully: {plaintext[-1] == file_data[i]}")

Sandra.write_data(
    file_names, # name of file to be written
    plaintext, # data to be written, must be same length as file_names
    path='./taylor_txt_ed' # path to write data to
) """


# RSA 
# file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
# enc_dec_rsa = Sandra.RSA(2048, Sandra.RSA_ENGINE_DOME)
# ciphertext = enc_dec_rsa.encrypt(file_data[0])
# print(len(ciphertext))
# plaintext = enc_dec_rsa.decrypt(ciphertext)
# print(plaintext == file_data[0])
# Sandra.write_data(
#     file_names, # name of file to be written
#     [plaintext], # data to be written, must be same length as file_names
#     path='./taylor_txt_ed' # path to write data to
# )



# #AES CFB
# iv   = bytes.fromhex('fffffe00000000000000000000000000')
# key  = bytes.fromhex('00000000000000000000000000000000')
# file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
# enc_dec_cfb = Sandra.AES(key, Sandra.MODE_CFB, iv, segment_size=16)
# ciphertext = enc_dec_cfb.encrypt(file_data[0])
# print(len(ciphertext))
# plaintext = enc_dec_cfb.decrypt(ciphertext)
# print(plaintext == file_data[0])
# Sandra.write_data(
#     file_names, # name of file to be written
#     [plaintext], # data to be written, must be same length as file_names
#     path='./taylor_txt_ed' # path to write data to
# )


# OpenPGP
# iv   = bytes.fromhex('fffffe00000000000000000000000000')
# key  = bytes.fromhex('00000000000000000000000000000000')
# file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt')
# print(len(file_data[0]))
# file_data_padded = Sandra.pad(file_data, Sandra.AES_BLOCK_SIZE) 
# print(len(file_data_padded[0]))
# enc_dec_pgp = Sandra.AES(key, Sandra.MODE_OPENPGP, iv)
# ciphertext = enc_dec_pgp.encrypt(file_data_padded[0])
# eiv, ciphertext = ciphertext[:18], ciphertext[18:]
# print(len(ciphertext))
# plaintext = enc_dec_pgp.decrypt(ciphertext)
# print(len(plaintext))
# plaintext = Sandra.unpad(plaintext,Sandra.AES_BLOCK_SIZE)
# print(len(plaintext))
# print(plaintext == file_data[0])
# Sandra.write_data(
#     file_names, # name of file to be written
#     [plaintext], # data to be written, must be same length as file_names
#     path='./taylor_txt_ed' # path to write data to
# )