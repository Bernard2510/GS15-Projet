from math import ceil
import os

"""
def file_to_binary(filename_path):
    with open(filename_path, mode='r') as file:
        data=file.read()
        return data
"""

def fetch_from_server(username,name):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        return lines[0]

def bits_to_hex(bits):
    return hex(int(bits, 2))

def hex_to_bits(hex):
    a=bin(int(hex, 16))
    return a[2:].zfill(len(a)-1)
    return bin(int(hex, 16))[2:]

def push_to_server(username,name,content):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    #if server doesnt exist
    try:
        os.mkdir(server_path)
    except OSError:
        pass
    #if user folder doesnt exist
    try:
        os.mkdir(user_path)
    except OSError:
        pass
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    with open(file_path,mode='w') as file:
        file.write(str(content))

def key_to_binary(key):
    bin_key=''.join(format(ord(x), '08b') for x in key)
    return bin_key


def bits_to_string(bytes):
    return ''.join([chr(int(x, 2)) for x in bytes])

def string_to_bits(string):
    str = ''.join('{:08b}'.format(ord(c)) for c in string)
    return str.ljust(BLOCK_SIZE * ceil(len(str)/BLOCK_SIZE), '0')

def split_to_blocks(msg, block_size):
    nb_block = ceil(len(msg)/block_size)
    res=[""]*nb_block
    for i in range(nb_block):
        res[i]=msg[i*block_size:(i+1)*block_size]
    return res

"""
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
"""

"""
def func_feistel(K,D):
    res = (int(K,base=2)+int(D,base=2)) % pow(2,16)
    return res
"""

def func_feistel2(K,D):
    return int(K,base=2)^int(D,base=2)


def feistel_encrypt(data,Key):
    #K0="0000000011111111"
    #K0=Key

    #if len(data)%2!=0: #pas utile normalement
        #data="0"+data


    G0=data[:int(len(data)/2)]
    D0=data[int(len(data)/2):]

    T=8
    for i in range(T):
        G1=D0
        D1Dec=int(G0,base=2)^func_feistel2(Key[i],D0)
        #D1="{0:b}".format(int(D1Dec))
        D1=bin(D1Dec)[2:].zfill(len(G0))

        #while len(D1)!=len(data)/2:
            #D1="0"+D1
        
        G0=G1
        D0=D1
        #K0=circularPermutation_left(K0)

        
    return G1+""+D1
    
    

def feistel_decrypt(data,Key):
    #K0=Key
    #K0="0000000011111111"
    #K1=circularPermutation_left(circularPermutation_left(K0))
    #print(K1)
    #K1 = "0000111111110000"

    G1=data[:int(len(data)/2)]
    D1=data[int(len(data)/2):]

    T=8
    for i in range(T):
        G0Dec=int(D1,base=2)^func_feistel2(Key[7-i],G1)
        #G0="{0:b}".format(int(G0Dec))
        G0=bin(G0Dec)[2:].zfill(len(D1))
        D0=G1
        
        #while len(G0)!=len(data)/2:
            #G0="0"+G0
        
        G1=G0
        D1=D0
        #K1=circularPermutation_rigth(K1)
    
    return G0+""+D0

def pad(msg,block_size):
    # pkcs7 padding
    padding=block_size-len(msg)%block_size
    for i in range(padding):
        msg=msg+"0"
    return msg




#feistel(file_to_binary("C:\\Users\\roman\\OneDrive\\Documents\\GitHub\\GS15-Projet\\server\\test\\test.txt"))
BLOCK_SIZE = 64
ROUNDS = 8

key = "AC3306BDFBD7585971FABD3ACBB4A71AA1C738C5D0D09CDBD95C92B58CCA6A45"
key2 = "4DC6A57A25633299E3A177FAED0EE3FB07A09B2FDCE6F64CA92C0C3879706B8E"
key3 = "FF209D105008F6645FE9E54F37499D6CC33BF2E2281F2B612D1BC0B9D2F8842B"
key4 = "1F9B454FEE1D1FF2A7A535DF5ED149416549932A5348ACE8B837AAFAB137FB5F"
key5 = "2B6D3DB9DEDE1BDF81525212ABA0847A6B85BE8E2B412C768E52DE308CA4BCB4"
k=key_to_binary(key4)
msg=fetch_from_server("alice","Message")
msg_bin=string_to_bits(msg)

msg_bin_tab=split_to_blocks(msg_bin,BLOCK_SIZE)
sub_key=split_to_blocks(k[0:256],int(BLOCK_SIZE/2))

tab_enc=[""]*len(msg_bin_tab)
for i in range(len(msg_bin_tab)):
    tab_enc[i]=feistel_encrypt(msg_bin_tab[i],sub_key)
    print(tab_enc[i])

print(tab_enc)

enc_string=""
for i in range(len(tab_enc)):
    enc_string=enc_string+tab_enc[i]
push_to_server("alice","enc_file",bits_to_hex(''.join(enc_string))[2:])

enc_msg=fetch_from_server("alice","enc_file")
tab_enc=split_to_blocks(hex_to_bits(enc_msg),BLOCK_SIZE)
print(tab_enc)


tab_dec=[""]*len(tab_enc)
for i in range(len(tab_enc)):
    tab_dec[i]=feistel_decrypt(tab_enc[i],sub_key)


t=""
e=""
d=""

for i in range(len(msg_bin_tab)):
    t=t+msg_bin_tab[i]
    e=e+tab_enc[i]
    d=d+tab_dec[i]

#print(d)
#print(t)
if d==t:
    print("ok")
print(bits_to_string(split_to_blocks(''.join(t), 8)))
#print(bits_to_string(split_to_blocks(''.join(e), 8)))
print(bits_to_string(split_to_blocks(''.join(d), 8)))






