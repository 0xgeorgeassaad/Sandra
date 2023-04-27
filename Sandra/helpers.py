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

