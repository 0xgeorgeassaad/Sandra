import os
def load_data(path='.'):
    if os.path.isdir(path):
        file_names = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
        file_data = []
        for name in file_names:
            with open(os.path.join(path, name), 'rb') as f:
                file_data.append(f.read())
    else:
        file_names = [os.path.basename(path)]
        file_data = []
        with open(path, 'rb') as f:
            file_data.append(f.read())
    return file_names, file_data



def write_data(file_names, file_data, path='.'):
    if not os.path.exists(path):
        os.mkdir(path)
    for name, data in zip(file_names, file_data):
        with open(os.path.join(path, name), 'wb') as f:
            f.write(data)

"""
    pkcs7 padding
"""
def pad(data, block_size=16):
    if isinstance(data, list):
        return [pad(i) for i in data]
    pad_len = block_size - len(data) % block_size
    return data + (bytes([pad_len]) * pad_len)

def unpad(data, block_size=16):
    if isinstance(data, list):
        return [unpad(i) for i in data]
    if ord(data[-1:]) > block_size:
        raise ValueError(f"Either data was not padded with {block_size} or block size is incorrect")
    return data[:-ord(data[-1:])]

def is_power_of_2(n):
    return (n & (n-1) == 0) and n != 0