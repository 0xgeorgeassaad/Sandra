from Crypto.Cipher import AES 
from . import sandra
from . import troy

import timeit
import pandas as pd

def performance_test(
        names, 
        files_data, 
        rsa_key_size=2048, 
        rsa_engine=troy.RSA_ENGINE_RAW,
        segment_size=16,
        verbose=True):
    files = dict(zip(names, files_data))

    iv   = bytes.fromhex('fffffe00000000000000000000000000')
    key  = bytes.fromhex('00000000000000000000000000000000')

    stats = dict()

    def run_n_times(mode_name, encryptor, decryptor, OPENPGP=0, n=100):
        if mode_name + '_enc' not in stats:
            stats[mode_name + '_enc'] = dict()
            stats[mode_name + '_dec'] = dict()
        for filename, file in files.items():
            ct = encryptor.encrypt(file)
            if OPENPGP == 1: # PyCrypto
                eiv, ct = ct[:18], ct[18:]
                decryptor = AES.new(key, AES.MODE_OPENPGP, eiv)
            elif OPENPGP == 2: # Sandra
                eiv, ct = ct[:18], ct[18:]
            t = timeit.Timer(
                lambda: encryptor.encrypt(file)
            )
            stats[mode_name + '_enc'][filename] = t.timeit(n) / n
            t = timeit.Timer(
                lambda: decryptor.decrypt(ct)
            )
            stats[mode_name + '_dec'][filename] = t.timeit(n) / n




    # PyCrypto CFB
    encryptor = AES.new(key, AES.MODE_CFB, iv, segment_size=segment_size)
    decryptor = AES.new(key, AES.MODE_CFB, iv, segment_size=segment_size)
    run_n_times(f'CFB_{segment_size}', encryptor, decryptor, n=1000)
    if verbose:
        print(f">> Finished running CFB_{segment_size} 1000 times")

    # PyCrypto OPENPGP
    encryptor = AES.new(key, AES.MODE_OPENPGP, iv)
    decryptor = None
    run_n_times('OPENPGP',encryptor, decryptor, OPENPGP=1, n=1000)
    if verbose:
        print(">> Finished running OPENPGP 1000 times")

    # Sandra CFB
    enc_dec_sandra = sandra.AES(key, sandra.MODE_CFB, iv, segment_size)
    run_n_times(f'CFB_SANDRA_{segment_size}', enc_dec_sandra, enc_dec_sandra, OPENPGP=0, n=100)
    if verbose:
        print(f">> Finished running CFB_SANDRA_{segment_size} 100 times")

    # Sandra OPENPGP
    enc_dec_sandra = sandra.AES(key, sandra.MODE_OPENPGP, iv)
    run_n_times('OPENPGP_SANDRA', enc_dec_sandra, enc_dec_sandra, OPENPGP=2, n=100)
    if verbose:
        print(">> Finished running OPENPGP_SANDRA 100 times")

    # Troy RSA (a wrapper around PyCrypto)
    enc_dec_rsa = troy.RSA(rsa_key_size, rsa_engine)
    run_n_times(f'RSA_TROY_{rsa_key_size}', enc_dec_rsa, enc_dec_rsa, n=100)
    if verbose:
        print(f">> Finished running RSA_TROY_{rsa_key_size} 100 times")

        print("============================================= Results (seconds) ============================================")
        df = pd.DataFrame.from_dict(stats, orient='index')
        print(df.to_string())
        
    return stats