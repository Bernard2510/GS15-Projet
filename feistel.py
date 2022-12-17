from math import ceil
import os


def fetch_from_server(username,name):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        return lines[0]

def binary_to_hexa(bits):
    return hex(int(bits, 2))

def hexa_to_binary(hex):
    hex=bin(int(hex, 16))[2:]
    pad=ceil(len(hex)/BLOCK_SIZE)*BLOCK_SIZE
    return hex.zfill(pad)

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


def binary_to_string(bits):
    return ''.join([chr(int(x, 2)) for x in bits])

def string_to_binary(string):
    str = ''.join('{:08b}'.format(ord(c)) for c in string)
    return str.ljust(BLOCK_SIZE * ceil(len(str)/BLOCK_SIZE), '0')

def split_to_blocks(msg, block_size):
    nb_block = ceil(len(msg)/block_size)
    res=[""]*nb_block
    for i in range(nb_block):
        res[i]=msg[i*block_size:(i+1)*block_size]
    return res



def xor(K,D):
    return int(K,base=2)^int(D,base=2)


def feistel_encrypt(data,key):
    G0=data[:int(len(data)/2)]
    D0=data[int(len(data)/2):]

    T=8
    for i in range(T):
        G1=D0
        D1Dec=int(G0,base=2)^xor(key[i],D0)
        D1=bin(D1Dec)[2:].zfill(len(G0))

        G0=G1
        D0=D1

        
    return G1+""+D1
    
    

def feistel_decrypt(data,key):
    G1=data[:int(len(data)/2)]
    D1=data[int(len(data)/2):]

    T=8
    for i in range(T):
        G0Dec=int(D1,base=2)^xor(key[7-i],G1)
        G0=bin(G0Dec)[2:].zfill(len(D1))
        D0=G1
        
        G1=G0
        D1=D0
    
    return G0+""+D0





BLOCK_SIZE = 64
ROUNDS = 8

key = "AC3306BDFBD7585971FABD3ACBB4A71AA1C738C5D0D09CDBD95C92B58CCA6A45"
key2 = "4DC6A57A25633299E3A177FAED0EE3FB07A09B2FDCE6F64CA92C0C3879706B8E"
key3 = "FF209D105008F6645FE9E54F37499D6CC33BF2E2281F2B612D1BC0B9D2F8842B"
key4 = "1F9B454FEE1D1FF2A7A535DF5ED149416549932A5348ACE8B837AAFAB137FB5F"
key5 = "2B6D3DB9DEDE1BDF81525212ABA0847A6B85BE8E2B412C768E52DE308CA4BCB4"

#choix de la clé
k=key_to_binary(key5)
#k=512 bits
#0-256 : key
#256-320 : iV

#récupère le message (fichier) à chiffrer
msg=fetch_from_server("alice","Message")
#convertion du message en binaire
msg_bin=string_to_binary(msg)

#IV
iv_init=k[BLOCK_SIZE*ROUNDS//2:BLOCK_SIZE*(ROUNDS//2+1)]
iv=iv_init
#div en bloc du message
msg_bin_tab=split_to_blocks(msg_bin,BLOCK_SIZE)
#div en bloc de la clé
sub_key=split_to_blocks(k[0:BLOCK_SIZE*ROUNDS//2],BLOCK_SIZE//2)
#tournés de feistel sur les blocs du message mode CBC
tab_enc=[""]*len(msg_bin_tab)
for i in range(len(msg_bin_tab)):
    msg_bin_tab[i]=xor(iv,msg_bin_tab[i])
    msg_bin_tab[i]=bin(msg_bin_tab[i])[2:].zfill(BLOCK_SIZE)
    tab_enc[i]=feistel_encrypt(msg_bin_tab[i],sub_key)
    iv=tab_enc[i]


#envoi du chiffré
enc_string=""
for i in range(len(tab_enc)):
    enc_string=enc_string+tab_enc[i]
push_to_server("alice","enc_file",binary_to_hexa(''.join(enc_string))[2:])


#recup du chiffré
enc_msg=fetch_from_server("alice","enc_file")
tab_enc=split_to_blocks(hexa_to_binary(enc_msg),BLOCK_SIZE)

#tournés de feistel sur les blocs du chiffré
#mode CBC
iv=iv_init
tab_dec=[""]*len(tab_enc)
for i in range(len(tab_enc)):
    tab_dec[i]=feistel_decrypt(tab_enc[i],sub_key)
    tab_dec[i]=xor(iv,tab_dec[i])
    tab_dec[i]=bin(tab_dec[i])[2:].zfill(BLOCK_SIZE)
    iv=tab_enc[i]


e=""
d=""

for i in range(len(msg_bin_tab)):
    e=e+tab_enc[i]
    d=d+tab_dec[i]

#message clair
print(msg)
#message chiffré hexa
print(binary_to_hexa(''.join(enc_string))[2:])
#message déchiffré
print(binary_to_string(split_to_blocks(''.join(d), 8)))






