def file_to_binary(filename_path):
    with open(filename_path, mode='r') as file:
        data=file.read()
        bin_data=''.join(format(ord(x), '08b') for x in data)
        return bin_data


def circularPermutation_left(K): #permutation 2 bits
    circlarString = ""
    for i in range(len(K)-2):
        circlarString=circlarString+""+K[i+2]
    circlarString=circlarString+""+K[0]
    circlarString=circlarString+""+K[1]
    return circlarString

def circularPermutation_rigth(K): #permutation 2 bits
    circlarString = ""
    circlarString=circlarString+""+K[len(K)-1]
    circlarString=circlarString+""+K[len(K)-2]
    for i in range(len(K)-2):
        circlarString=circlarString+""+K[i]
    return circlarString

def func_fesitel(K,D):
    res = int(K,base=2)+int(D,base=2) % 2**16
    return "{0:b}".format(int(res))

def feistel_encrypt(data):
    K0="0000000011111111"

    if len(data)%2!=0: #pas utile normalement
        data="0"+data

    G0=""
    D0=""
    for i in range(int(len(data)/2)):
        G0 = G0+""+data[i]
        D0 = D0+""+data[i+int(len(data)/2)]

    T=3
    for i in range(T):
        G1=D0
        D1=int(G0,base=2)^int(func_fesitel(K0,D0),base=2)
        D1="{0:b}".format(int(D1))
        
        while len(D1)!=len(data)/2:
            D1="0"+D1
        
        G0=G1
        D0=D1
        K0=circularPermutation_left(K0)
    
    return G1+""+D1
    

def feistel_decrypt(data):
    K1 = "0000111111110000"

    G1=""
    D1=""
    for i in range(int(len(data)/2)):
        G1 = G1+""+data[i]
        D1 = D1+""+data[i+int(len(data)/2)]

    T=3
    for i in range(T):
        G0=int(D1,base=2)^int(func_fesitel(K1,G1),base=2)
        G0="{0:b}".format(int(G0))
        D0=G1
        
        while len(G0)!=len(data)/2:
            G0="0"+G0
        
        G1=G0
        D1=D0
        K1=circularPermutation_rigth(K1)
    
    return G0+""+D0


#feistel(file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\test\\test.txt"))

print(feistel_encrypt("01000111010100110011000100110101"))
print(feistel_decrypt("01001000010101100010110100100001"))
