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
### RSA File Encryption using [PKCS#1 OAEP](https://datatracker.ietf.org/doc/html/rfc8017)
```python
import Sandra
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
    file_names, # name of file to be written
    [plaintext], # data to be written, must be same length as file_names
    path='./taylor_txt_ed' # path to write data to
)
```

### AES OpenPGP-CFB Mode File Encryption
> In This mode, the first 18 bytes of cipher text contain the encrypted IV
```python
import Sandra
iv   = bytes.fromhex('fffffe00000000000000000000000000')
key  = bytes.fromhex('00000000000000000000000000000000')
file_names, file_data = Sandra.load_data('./taylor_txt/taylor_swift_1KB.txt') 
enc_dec_pgp = Sandra.AES(key, Sandra.MODE_OPENPGP, iv, segment_size=16)
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
```

## Performance
To obtain a table like this one, run 
```python
import Sandra
file_names, file_data = Sandra.load_data('path/to/data')
Sandra.performance_test(file_names, file_data)
```

|                    |   taylor_swift_1KB.txt |   taylor_swift_10KB.txt |   taylor_swift_100KB.txt |   taylor_swift_5KB.txt |
|:-------------------|-----------------------:|------------------------:|-------------------------:|-----------------------:|
| CFB_enc            |            3.20184e-05 |             0.000228404 |              0.0022509   |            0.000106322 |
| CFB_dec            |            2.25229e-05 |             0.000222947 |              0.00330419  |            9.85432e-05 |
| OPENPGP_enc        |            5.70565e-06 |             3.0201e-05  |              0.000280344 |            1.57004e-05 |
| OPENPGP_dec        |            6.0602e-06  |             3.05637e-05 |              0.000297508 |            1.55763e-05 |
| OPENPGP_SANDRA_enc |            0.000358904 |             0.00407359  |              0.0492199   |            0.00173748  |
| OPENPGP_SANDRA_dec |            0.000388411 |             0.00396413  |              0.063188    |            0.00174934  |
| RSA_TROY_enc       |            0.00453846  |             0.0412725   |              0.463819    |            0.0194584   |
| RSA_TROY_dec       |            0.0323089   |             0.15982     |              1.38922     |            0.0765507   |

