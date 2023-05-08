# Sandra
![logo](https://user-images.githubusercontent.com/26662104/234409378-4602ff85-8fb1-425d-9213-979876c78dcc.png)

**Sandra implements CFB and  [OpenPGP-CFB](https://datatracker.ietf.org/doc/html/rfc4880) built on top of pycryptodome.**

## Usage
### Loading Data
```python
Sandra.load_data(
    path # str -> path to data to be loaded
)
```
### Writing Data
 ```python
Sandra.write_data(
    file_names, # name of files to be written
    file_data, # data to be written, must be the same length as file_names
    path='.' # path to write data to
)
```

## Examples
### RSA File Encryption 
```python
import Sandra
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
enc_dec_rsa = Sandra.RSA(2048, Sandra.RSA_ENGINE_DOME)
ciphertext = enc_dec_rsa.encrypt(file_data[0])
print(len(ciphertext))
plaintext = enc_dec_rsa.decrypt(ciphertext)
print(plaintext == file_data[0])
Sandra.write_data(
    file_names, # name of the file to be written
    [plaintext], # data to be written, must be the same length as file_names
    path='./taylor_txt_ed' # path to write data to
)
```

### AES CFB Mode Sample(NIST) Encryption
```python
import Sandra
#Test Case from http://csrc.nist.gov/groups/STM/cavp/block-ciphers.html#aes
data = bytes.fromhex('fffffe00000000000000000000000000')
iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')

enc_dec_sandra = Sandra.AES(key, Sandra.MODE_CFB, iv, segment_size=16)
ciphertext = enc_dec_sandra.encrypt(data)
plaintext = enc_dec_sandra.decrypt(ciphertext)
```

### AES CFB Mode File Encryption
```python
import Sandra
iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
enc_dec_cfb = Sandra.AES(key, Sandra.MODE_CFB, iv, segment_size=16)
ciphertext = enc_dec_cfb.encrypt(file_data[0])
print(len(ciphertext))
plaintext = enc_dec_cfb.decrypt(ciphertext)
print(plaintext == file_data[0])
Sandra.write_data(
    file_names, # name of the file to be written
    [plaintext], # data to be written, must be same length as file_names
    path='./taylor_txt_ed' # path to write data to
)
```

### AES OpenPGP-CFB Mode File Encryption
> In This mode, the first 18 bytes of cipher text contain the encrypted IV
> Padding here is unnecessary as this mode is a stream cipher
```python
import Sandra
iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt')
print(len(file_data[0]))
file_data_padded = Sandra.pad(file_data, Sandra.AES_BLOCK_SIZE) 
print(len(file_data_padded[0]))
enc_dec_pgp = Sandra.AES(key, Sandra.MODE_OPENPGP, iv)
ciphertext = enc_dec_pgp.encrypt(file_data_padded[0])
eiv, ciphertext = ciphertext[:18], ciphertext[18:]
print(len(ciphertext))
plaintext = enc_dec_pgp.decrypt(ciphertext)
print(len(plaintext))
plaintext = Sandra.unpad(plaintext,Sandra.AES_BLOCK_SIZE)
print(len(plaintext))
print(plaintext == file_data[0])
Sandra.write_data(
    file_names, # name of the file to be written
    [plaintext], # data to be written, must be the same length as file_names
    path='./taylor_txt_ed' # path to write data to
)
```

## Performance
To obtain a table like this one, run 
```python
import Sandra
file_names, file_data = Sandra.load_data('path/to/data')
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
```
![image](https://user-images.githubusercontent.com/26662104/236880905-4862877c-1fec-4662-831a-a8cdd5781a2d.png)
