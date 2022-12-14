def file_to_binary(filename_path):
    with open(filename_path, mode='r') as file:
        data=file.read()
        bin_data=''.join(format(ord(x), '08b') for x in data)
        return bin_data

def key_to_binary(key):
    bin_key=''.join(format(ord(x), '08b') for x in key)
    return bin_key

#https://www.geeksforgeeks.org/python-program-to-convert-binary-to-ascii/
def binary_to_ascii(bin):
    binary_int = int(bin, 2)
    byte_number = binary_int.bit_length() + 7 // 8
    binary_array = binary_int.to_bytes(byte_number, "big")
    ascii_text = binary_array.decode()
    print(ascii_text)



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
    res = (int(K,base=2)+int(D,base=2)) % pow(2,256)
    return res


def feistel_encrypt(data,Key):
    #K0="0000000011111111"
    K0=Key

    #if len(data)%2!=0: #pas utile normalement
        #data="0"+data


    G0=data[:int(len(data)/2)]
    D0=data[int(len(data)/2):]

    T=3
    for i in range(T):
        G1=D0
        D1Dec=int(G0,base=2)^func_feistel(K0,D0)
        #D1="{0:b}".format(int(D1Dec))
        D1=bin(D1Dec)[2:].zfill(len(G0))

        #while len(D1)!=len(data)/2:
            #D1="0"+D1
        
        G0=G1
        D0=D1
        K0=circularPermutation_left(K0)
    
    return G1+""+D1
    

def feistel_decrypt(data,Key):
    K0=Key
    #K0="0000000011111111"
    K1=circularPermutation_left(circularPermutation_left(K0))
    #print(K1)
    #K1 = "0000111111110000"

    G1=data[:int(len(data)/2)]
    D1=data[int(len(data)/2):]

    T=3
    for i in range(T):
        G0Dec=int(D1,base=2)^func_feistel(K1,G1)
        #G0="{0:b}".format(int(G0Dec))
        G0=bin(G0Dec)[2:].zfill(len(D1))
        D0=G1
        
        #while len(G0)!=len(data)/2:
            #G0="0"+G0
        
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




#feistel(file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\test\\test.txt"))

key = "AC3306BDFBD7585971FABD3ACBB4A71AA1C738C5D0D09CDBD95C92B58CCA6A45"
key2 = "4DC6A57A25633299E3A177FAED0EE3FB07A09B2FDCE6F64CA92C0C3879706B8E" #non
key3 = "FF209D105008F6645FE9E54F37499D6CC33BF2E2281F2B612D1BC0B9D2F8842B"
key4 = "1F9B454FEE1D1FF2A7A535DF5ED149416549932A5348ACE8B837AAFAB137FB5F"
key5 = "2B6D3DB9DEDE1BDF81525212ABA0847A6B85BE8E2B412C768E52DE308CA4BCB4"
k=key_to_binary(key)

a=file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\alice\\Message.txt")

msg=(pad(a))
enc=feistel_encrypt(msg,k)
hex_enc=hex(int(enc, 2))
print(hex_enc[2:])
dec=feistel_decrypt(enc,k)
binary_to_ascii(dec)



