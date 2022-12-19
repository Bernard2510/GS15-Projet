import os
import random
import hashlib
from math import ceil

class Utilisateur:

    def __init__(self,username):
        self.name = username; #nom de l'utilisateur
        self.idPrivKey = "" #ID clé privée
        self.idPubKey = "" #ID clé publique
        self.preSignPubKey = "" #clé publique présignée
        self.preSignPrivKey = "" #clé privée présignée
        self.otPrivKey = [] #liste de clés one time session privée
        self.otPubKey = [] #liste de clés one time session privée
        self.SK = "" #clé partagé

        self.rootRatchet = SymmRatchet
        self.sendRatchet = SymmRatchet
        self.recvRatchet = SymmRatchet

        self.RPrivKey = ""  #double ratchet
        self.RPubKey = ""



class Bundle:

    def __init__(self):
        self.idPubKey = "" #ID clé publique
        self.preSignPubKey = "" #clé publique présignée
        self.otPKn = "" #liste de clés one time session
        self.n = "" #numéro one time key utilisee

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


def fetch_from_server(username,name):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        return lines[0]

def remove_from_server(username,name):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    os.remove(file_path)

def remove_user(username):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    os.rmdir(user_path)

"""
Feistel
"""
def string_to_binary(string,block_size):
    str = ''.join('{:08b}'.format(ord(c)) for c in string)
    return str.ljust(block_size * ceil(len(str)/block_size), '0')

def split_to_blocks(msg, block_size):
    nb_block = ceil(len(msg)/block_size)
    res=[""]*nb_block
    for i in range(nb_block):
        res[i]=msg[i*block_size:(i+1)*block_size]
    return res

def key_to_binary(key):
    bin_key=''.join(format(ord(x), '08b') for x in key)
    return bin_key

def binary_to_hexa(bits):
    return hex(int(bits, 2))

def hexa_to_binary(hex,block_size):
    hex=bin(int(hex, 16))[2:]
    pad=ceil(len(hex)/block_size)*block_size
    return hex.zfill(pad)

def binary_to_string(bits):
    return ''.join([chr(int(x, 2)) for x in bits])

def xor(K,D):
    return int(K,base=2)^int(D,base=2)

def feistel_encrypt(data,key,rounds):
    G0=data[:int(len(data)/2)]
    D0=data[int(len(data)/2):]
    T=rounds
    for i in range(T):
        G1=D0
        D1Dec=int(G0,base=2)^xor(key[i],D0)
        D1=bin(D1Dec)[2:].zfill(len(G0))

        G0=G1
        D0=D1  
    return G1+""+D1
    
def feistel_decrypt(data,key,rounds):
    G1=data[:int(len(data)/2)]
    D1=data[int(len(data)/2):]
    T=rounds
    for i in range(T):
        G0Dec=int(D1,base=2)^xor(key[7-i],G1)
        G0=bin(G0Dec)[2:].zfill(len(D1))
        D0=G1
        
        G1=G0
        D1=D0
    return G0+""+D0

"""
-----------------------------
"""

def gen_key_pair():
    p = 11476114425077445636913897780729058814788399522553701049280397688323001276391084717487591797788773737035134819088321086678078901084786890698833590212793893
    g = 5
    priv = random.randrange(2, p-1)
    pub = pow(g,priv,p)
    return priv, pub


def generate_bundle(user):
    user.idPrivKey, user.idPubKey = gen_key_pair()
    user.preSignPrivKey, user.preSignPubKey = gen_key_pair() #signé avec idPrivK, idPubK
    user.otPrivKey = [0]*MAX_OTPK
    user.otPubKey = [0]*MAX_OTPK
    for i in range(MAX_OTPK):
        user.otPrivKey[i], user.otPubKey[i]=gen_key_pair()


def publish_bundle(user):
    push_to_server(user.name,"idPubKey",user.idPubKey)
    push_to_server(user.name,"preSignPubKey",user.preSignPubKey)
    for i in range(len(user.otPubKey)):
        push_to_server(user.name,"otPubKey"+str(i),user.otPubKey[i])


def get_user_bundle(username):
    bundle = Bundle()
    bundle.idPubKey = fetch_from_server(username,"idPubKey")
    bundle.preSignPubKey = fetch_from_server(username,"preSignPubKey")
    bundle.n = random.randrange(MAX_OTPK)
    bundle.otPKn = fetch_from_server(username,"otPubKey"+str(bundle.n))
    return bundle

def establish_session(receiver):
    receiverBundle=get_user_bundle(receiver.name)
    EphPrivK,EphPubK = gen_key_pair()
    return receiverBundle, EphPrivK, EphPubK

def DH(a,B):
    p = 11476114425077445636913897780729058814788399522553701049280397688323001276391084717487591797788773737035134819088321086678078901084786890698833590212793893
    return pow(int(B),int(a),p)

import hmac
import hashlib
import binascii

def create_sha256_signature(key, message):
    if len(key)%2 != 0:
        key=key+"0"
    byte_key = binascii.unhexlify(key)
    message = message.encode()
    return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()

def x3dh_sender(sender, receiver):
    receiverBundle, EphPrivK, EphPubK = establish_session(receiver)
    #verif signature
    DH1 = DH(sender.idPrivKey,receiverBundle.preSignPubKey)
    DH2 = DH(EphPrivK,receiverBundle.idPubKey)
    DH3 = DH(EphPrivK,receiverBundle.preSignPubKey)
    DH4 = DH(EphPrivK,receiverBundle.otPKn)

    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    SK = create_sha256_signature(DHf,"INIT")
    sender.SK=SK
    #supp DH1, 2, 3, 4 et EphPrivK, EphPubK
    x3dh_receiver(sender.idPubKey, EphPubK, receiverBundle.n, receiver) 

#when online
def x3dh_receiver(sender_idPubK, sender_EphPubK, n, receiver):
    DH1 = DH(receiver.preSignPrivKey, sender_idPubK)
    DH2 = DH(receiver.idPrivKey, sender_EphPubK)
    DH3 = DH(receiver.preSignPrivKey, sender_EphPubK)
    DH4 = DH(receiver.otPrivKey[n],sender_EphPubK)
    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    SK = create_sha256_signature(DHf,"INIT")
    receiver.SK=SK
    #supp DH1, 2, 3, 4 et EphPrivK, EphPubK



class SymmRatchet:

    def __init__(self, key):
        self.chainKey = key


def init_ratchets(user,order):
    # initialise the root chain with the shared key
    user.rootRatchet = SymmRatchet(user.SK)
    # initialise the sending and recving chains
    if order == 1:
        user.sendRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
        user.recvRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
    else:
        user.recvRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
        user.sendRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
    # initialise DH key
    user.RPrivKey, user.RPubKey = gen_key_pair()
    push_to_server(user.name,"RPubKey",user.RPubKey)


def turn_ratchet(ratchet):
    C1="0x01"
    C2="0x02"
    messageKey = create_sha256_signature(ratchet.chainKey,C1)
    ratchet.chainKey = create_sha256_signature(ratchet.chainKey,C2)
    return messageKey

def turn_ratchet_DH(ratchet,dh):
    output = create_sha256_signature(ratchet.chainKey,str(dh))
    ratchet.chainKey = output[:32]
    messageKey = output[32:]
    return messageKey

#MAIN INIT X3DH
MAX_OTPK=5
alice=Utilisateur("alice")
generate_bundle(alice)
publish_bundle(alice)

bob=Utilisateur("bob")
generate_bundle(bob)
publish_bundle(bob)
x3dh_sender(bob,alice)

#MAIN INIT DOUBLE RATCHET
init_ratchets(alice,1)
init_ratchets(bob,2)



def sendMessage(sender,receiverName,message):
    sender.RPrivKey, sender.RPubKey = gen_key_pair()
    push_to_server(sender.name,"RPubKey",sender.RPubKey)
    receiverPubKey=fetch_from_server(receiverName,"RPubKey")
    RDH=DH(sender.RPrivKey,receiverPubKey)
    push_to_server(sender.name,"Message",message)
    sender.sendRatchet.chainKey=turn_ratchet_DH(sender.rootRatchet,RDH)
    messageKey=turn_ratchet(sender.sendRatchet)
    return message+messageKey


def receiveMessage(receiver,senderName):
    message=fetch_from_server(senderName,"Message")
    senderPubKey=fetch_from_server(senderName,"RPubKey")
    RDH=DH(receiver.RPrivKey,senderPubKey)
    #decode message
    receiver.recvRatchet.chainKey=turn_ratchet_DH(receiver.rootRatchet,RDH)
    messageKey=turn_ratchet(receiver.recvRatchet)
    receiver.RPrivKey, receiver.RPubKey = gen_key_pair()
    push_to_server(receiver.name,"RPubKey",receiver.RPubKey)
    return message, messageKey

def sendMessageKey(sender,receiverName):
    sender.RPrivKey, sender.RPubKey = gen_key_pair()
    push_to_server(sender.name,"RPubKey",sender.RPubKey)
    receiverPubKey=fetch_from_server(receiverName,"RPubKey")
    RDH=DH(sender.RPrivKey,receiverPubKey)
    sender.sendRatchet.chainKey=turn_ratchet_DH(sender.rootRatchet,RDH)
    messageKey=turn_ratchet(sender.sendRatchet)
    return messageKey


def receiveMessageKey(receiver,senderName):
    senderPubKey=fetch_from_server(senderName,"RPubKey")
    RDH=DH(receiver.RPrivKey,senderPubKey)
    #decode message
    receiver.recvRatchet.chainKey=turn_ratchet_DH(receiver.rootRatchet,RDH)
    messageKey=turn_ratchet(receiver.recvRatchet)
    receiver.RPrivKey, receiver.RPubKey = gen_key_pair()
    push_to_server(receiver.name,"RPubKey",receiver.RPubKey)
    return messageKey


def sendFile(sender,receiverName,fileName):
    BLOCK_SIZE = 64
    ROUNDS = 8

    #recup clé d'envoi
    k=key_to_binary(sendMessageKey(sender,receiverName))
    #k=512 bits
    #0-256 : key
    #256-320 : iV

    #récupère le message (fichier) à chiffrer
    msg=fetch_from_server(sender.name,fileName)
    #convertion du message en binaire
    msg_bin=string_to_binary(msg,BLOCK_SIZE)

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
        tab_enc[i]=feistel_encrypt(msg_bin_tab[i],sub_key,ROUNDS)
        iv=tab_enc[i]


    #envoi du chiffré
    enc_string=""
    for i in range(len(tab_enc)):
        enc_string=enc_string+tab_enc[i]
    push_to_server(sender.name,"enc_file",binary_to_hexa(''.join(enc_string))[2:])


def ReceiveFile(receiver,senderName,fileName):
    BLOCK_SIZE = 64
    ROUNDS = 8

    #recup clé de reception
    k=key_to_binary(receiveMessageKey(receiver,senderName))
    sub_key=split_to_blocks(k[0:BLOCK_SIZE*ROUNDS//2],BLOCK_SIZE//2)
    #recup du chiffré
    enc_msg=fetch_from_server(senderName,"enc_file")
    tab_enc=split_to_blocks(hexa_to_binary(enc_msg,BLOCK_SIZE),BLOCK_SIZE)

    #tournés de feistel sur les blocs du chiffré
    #mode CBC
    dec_string=""
    #IV
    iv_init=k[BLOCK_SIZE*ROUNDS//2:BLOCK_SIZE*(ROUNDS//2+1)]
    iv=iv_init
    tab_dec=[""]*len(tab_enc)
    for i in range(len(tab_enc)):
        tab_dec[i]=feistel_decrypt(tab_enc[i],sub_key,ROUNDS)
        tab_dec[i]=xor(iv,tab_dec[i])
        tab_dec[i]=bin(tab_dec[i])[2:].zfill(BLOCK_SIZE)
        iv=tab_enc[i]
        dec_string=dec_string+tab_dec[i]

    push_to_server(receiver.name,"Receive_Message",binary_to_string(split_to_blocks(''.join(dec_string), 8)))
    

sendFile(alice,bob.name,"Send_Message")
ReceiveFile(bob,alice.name,"test")
"""
print(sendMessage(bob,alice.name,"hello"))
print(receiveMessage(alice,bob.name))
print(sendMessage(alice,bob.name,"bonjour"))
print(receiveMessage(bob,alice.name))
"""





