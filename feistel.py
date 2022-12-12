def file_to_binary(filename_path):
    with open(filename_path, mode='r') as file:
        data=file.read()
        bin_data=''.join(format(ord(x), '08b') for x in data)
        return bin_data

def key_to_binary(key):
    bin_key=''.join(format(ord(x), '08b') for x in key)
    return bin_key



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

def func_feistel(K,D):
    res = int(K,base=2)+int(D,base=2) % 2**512
    return "{0:b}".format(int(res))

def feistel_encrypt(data,Key):
    #K0="0000000011111111"
    K0=Key

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
        D1=int(G0,base=2)^int(func_feistel(K0,D0),base=2)
        D1="{0:b}".format(int(D1))
        
        while len(D1)!=len(data)/2:
            D1="0"+D1
        
        G0=G1
        D0=D1
        K0=circularPermutation_left(K0)
    
    return G1+""+D1
    

def feistel_decrypt(data,Key):
    K0=Key
    K1=circularPermutation_left(circularPermutation_left(circularPermutation_left(K0)))
    print(K1)
    #K1 = "0000111111110000"

    G1=""
    D1=""
    for i in range(int(len(data)/2)):
        G1 = G1+""+data[i]
        D1 = D1+""+data[i+int(len(data)/2)]

    T=3
    for i in range(T):
        G0=int(D1,base=2)^int(func_feistel(K1,G1),base=2)
        G0="{0:b}".format(int(G0))
        D0=G1
        
        while len(G0)!=len(data)/2:
            G0="0"+G0
        
        G1=G0
        D1=D0
        K1=circularPermutation_rigth(K1)
    
    return G0+""+D0

def pad(msg):
    # pkcs7 padding
    padding=(512*2)-len(msg)
    for i in range(padding):
        msg=msg+"0"
    return msg


def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]

#feistel(file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\test\\test.txt"))
key = "AC3306BDFBD7585971FABD3ACBB4A71AA1C738C5D0D09CDBD95C92B58CCA6A45"
key2 = "4DC6A57A25633299E3A177FAED0EE3FB07A09B2FDCE6F64CA92C0C3879706B8E"
print(len(key_to_binary(key)))
print(len(key_to_binary(key2)))
k=key_to_binary(key)
print("\n")
a=file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\alice\\Message.txt")
print(a)
msg=(pad(a))
print("\n-----------")
enc=feistel_encrypt(msg,k)
dec=feistel_decrypt(enc,k)
import binascii
print("\n")
print(dec)
#print(binascii.b2a_uu(dec))


#print(feistel_encrypt("01000111010100110011000100110101"))
#print(feistel_decrypt("01001000010101100010110100100001"))
