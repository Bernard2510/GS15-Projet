def file_to_binary(filename_path):
    with open(filename_path, mode='r') as file:
        data=file.read()
        bin_data=''.join(format(ord(x), '08b') for x in data)
        return bin_data

def feistel(data):

    if len(data)%2!=0: #pas utile normalement
        data="0"+data

    G0=""
    D0=""
    print(int(len(data)/2))
    for i in range(int(len(data)/2)):
        G0 = G0+""+data[i]
        D0 = D0+""+data[i+int(len(data)/2)]

    print(G0)
    print("")
    print(D0)


feistel(file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\test\\test.txt"))