
def tokenize(data):
    for i in range(len(data)-3):
        yield data[i:i+4]+ b'$'
