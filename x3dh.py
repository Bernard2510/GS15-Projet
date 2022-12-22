import os
import random
from random import randrange
import hashlib
from math import ceil
import secrets
import gmpy2


class Utilisateur:

    def __init__(self,username):
        self.name = username; #nom de l'utilisateur
        self.idPrivKey = "" #ID clé privée
        self.idPubKey = "" #ID clé publique
        self.preSignPubKey = "" #clé publique présignée
        self.preSignPrivKey = "" #clé privée présignée
        self.SignSPKPub = [] #liste de clés publiques présignées signées
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
        self.SignSPKPub = [] #signature de la clé publique présignée
        self.otPKn = "" #liste de clés one time session
        self.n = "" #numéro one time key utilisee


class SymmRatchet:

    def __init__(self, key):
        self.chainKey = key

"""
===============================================================
Fonction intéraction avec serveur
(envoi/suppression de fichier)
===============================================================
"""

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
    
    filename = name
    file_path=os.path.join(user_path,filename)
    with open(file_path,mode='w') as file:
        file.writelines(str(content))
        


def fetch_from_server(username,name):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name
    file_path=os.path.join(user_path,filename)
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        string=""
        for l in lines:
            string=string+str(l)

        return string

def remove_from_server(username,name):
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name
    file_path=os.path.join(user_path,filename)
    os.remove(file_path)


"""
===============================================================
===============================================================
"""


"""
===============================================================
Fonction algorithmique pour générations des différentes clés
===============================================================
"""
def concat(x,y):
    c_x=str(x)
    c_y=str(y)
    return (int(c_x+c_y))


def quotient(a,b):
    return a // b


def reste(a,b):
    return a % b


def rabin_miller(n,k): #Vérifie si n est un nombre premier, k nombre itérations de l'algo
    if n==2 or n==3:
        return True
    if n%2==0:
        return False

    if n > 31:
        if n%3==0 or n%5==0 or n%7==0 or n%11==0 or n%13==0 or n%17==0 or n%19==0 or n%23==0 or n%29==0 or n%31==0:
            return False    
    r=0
    s=n-1

    while s%2==0:
        r+=1
        s//=2

    for i in range(k):
        a=randrange(2,n-1)
        x=pow(a,s,n)
        if x==1 or x==n-1:
            continue
        
        for i in range(r-1):
            x=pow(x,2,n)
            if x==n-1:
                break
        else:
            return False
    
    return True


def gen_prime(longueur): #Génère un nombre premier suivant sa longueur
    
    nombreAlea = secrets.randbits(longueur)
    
    while gmpy2.is_prime(nombreAlea,25)==False:
        nombreAlea = secrets.randbits(longueur)   
    
    prime=nombreAlea
   
    return prime


def gen_safeprime(): #Génère un nombre fortement premier
    
    while True:
        p = gen_prime(2048)
        if gmpy2.is_prime((p-1)//2)==True:
            print("p : ",p)
            print(p.bit_length())
            return p


def gen_elementgen(p): #Génère un élement générateur avec pour paramètre un nombre fortement premier
    q=(p-1)//2
    while True:
        alpha = secrets.randbits(512)
        if pow(alpha,2,p)!=1 & pow(alpha,q,p)!=1 & pow(alpha,p-1,p)==1:
            print("alpha:",alpha)
            print("alpha^2:",pow(alpha,2,p))
            print("alpha^q:",pow(alpha,(p-1)//2,p))
            print("alpha^p-1:",pow(alpha,p-1,p))
            return alpha


def gen_IDKey(): #Permet de générer les clés identités d'un utilisateur

    print("Génération des clés identités :")
    choix = ""
    
    while True:
        choix = input("Ecrivez (1) pour laisser les clés par défaut pour démonstration, écrivez (2) pour générer de nouvelles clés identités.\n")
        if choix =="1":
            print("Vous avez choisi les paramètres par défaut.")
            p = 25275318963339501038904470567825138989060892737850578690358537231136482965510643268892699094003169567172687775542517182268676187800707418045999665720755350062432181515161865056719921816903657186723467176816222260278298693819846695171242366160403294103543366955861293307465384792437392827099649684774492739181210624829503989085343109951316675541243576941969934847161707999715528313403784352129647086251514324416816696320411947050545430487590651368224606778237019311251049555852486530156354038756890813023254935463876763698020345356943388292880124193038709698210894884428260734105918833601964994252759024480315396597759 #2048  #à générer avec l'algorithme au dessus
            push_to_server("","Value_P.txt",p)
            print("p: ",p)
            g = gen_elementgen(p) 
            IDpriv = secrets.randbits(2048)
            IDpub =pow(g,IDpriv,p)
            return IDpriv, IDpub
        if choix =="2":
            print("Vous avez choisi de générer un nouveau couple de clés.")
            p = gen_safeprime()
            push_to_server("","Value_P.txt",p)
            g = gen_elementgen(p)
            IDpriv = secrets.randbits(2048)
            IDpub =pow(g,IDpriv,p)
            return IDpriv, IDpub

"""
===============================================================
===============================================================
"""


"""
===============================================================
Signature DSA 
(génération, signature et vérification)
===============================================================
"""
def genkeyDSA(username,IDpriv): #On génère p, q, k tel que p-1=k*q avec p et q premier cependant pour faciliter les calculs on a pris k=2 et on se retrouve sur un problème d'existence d'un élément fortement premier

    x=IDpriv
    print("Génération des clés DSA :")
    
    p=int(fetch_from_server("","Value_P.txt"))

    print("p: ",p)
    q = (p-1)//2 
    print(rabin_miller(q,25))
    k = 2
    if(p-1==k*q):
        print("good")

    h = randrange(1,p-1)
    g = pow(h,k,p)
    while g<1:
            h = randrange(1,p-1)
            print(h)
    y = pow(g,x,p)
    
    print("p:",p)
    print("q:",q)
    print("x:",x)
    print("g:",g)
    print("y:",y) 
#a voir après supprimer les anciennes clés quand on relance le programme
    push_to_server(username,"PARAMSignPubKey_P.txt",p)
    push_to_server(username,"PARAMSignPubKey_Q.txt",q)
    push_to_server(username,"PARAMSignPubKey_G.txt",g)
    push_to_server(username,"PARAMSignPubKey_Y.txt",y)

    return p,q,g,y
    #p,q,g,y = clé publique et x = clé privé, h est le hache du message

def signDSA(p,q,g,IDpriv,M): #On signe le message avec la clé privée ID et les clés publiques DSA
    
    x=IDpriv
    hash = int(hashlib.sha256(M.encode('utf-8')).hexdigest(),16)
    print("hash :",hash)

    s = randrange(1,q)
    s1 = pow(g,s,p)%q
    s2 = (hash+s1*x)*pow(s,-1,q)%q 

    while (s1==0 & s2==0):
        s = randrange(1,q)
        s1 = pow(g,s,p)%q
        s2 = ((hash+s1*x)*pow(s,-1,q))%q

    print("s :",s)
    print("s1: ",s1)
    print("s2 :",s2)

    return s1,s2

def verifDSA(s1,s2,p,q,g,y,M): #Permet de vérifier la signature DSA
   
    if (s1<0 | s1>q) & (s2<0 & s2>q):
        print("Valeur signature erronée")
        return False
    
    hash = int(hashlib.sha256(M.encode('utf-8')).hexdigest(),16)
    print("hash :",hash)

    w = pow(s2,-1,q)
    u1 = (hash*w)%q
    u2 = (s1*w)%q
    v= (pow(g,u1,p)*pow(y,u2,p)%p)%q
    print("w: ",w)
    print("u1 :",u1)
    print("u2 :",u2)
    print("v: ",v)

    if v==s1:
        print("Signature validé")
        return True
    else:
        print("Signature non-valide")
        return False

"""
===============================================================
===============================================================
"""


"""
Feistel
"""
def string_to_binary(string):
    str = ''.join('{:08b}'.format(ord(c)) for c in string)
    return str

def padding(bin_string,block_size):
    return bin_string.ljust(block_size * ceil(len(bin_string)/block_size), '0')


def split_to_blocks(msg, block_size):
    nb_block = ceil(len(msg)/block_size)
    res=[""]*nb_block
    for i in range(nb_block):
        res[i]=msg[i*block_size:(i+1)*block_size]
    return res

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
    p = fetch_from_server("","Value_P.txt")

    gen1 = secrets.randbits(512)
    priv=pow(int(gen1),1,int(p))
    gen2 = secrets.randbits(512)
    pub=pow(int(gen2),1,int(p))
    return priv, pub

def gen_signKey(username,key,IDPrivKey):
    genkeyDSA(username,IDPrivKey)
    p = fetch_from_server("","Value_P.txt")
    q = fetch_from_server(username,"PARAMSignPubKey_Q.txt")
    g = fetch_from_server(username,"PARAMSignPubKey_G.txt")
    s1,s2 = signDSA(int(p),int(q),int(g),int(IDPrivKey),str(key)) #ici key représente le message dans la fonction DSA originale
    return s1,s2

def generate_bundle(user):
    user.idPrivKey, user.idPubKey = gen_IDKey()
    user.preSignPrivKey, user.preSignPubKey = gen_key_pair() #signé avec idPrivK, idPubK
    user.otPrivKey = [0]*MAX_OTPK
    user.otPubKey = [0]*MAX_OTPK
    user.SignSPKPub = [0]*2
    user.SignSPKPub[0], user.SignSPKPub[1]=gen_signKey(user.name,user.preSignPubKey,user.idPrivKey)
    for i in range(MAX_OTPK):
        user.otPrivKey[i], user.otPubKey[i]=gen_key_pair()


def publish_bundle(user):
    push_to_server(user.name,"idPubKey.txt",user.idPubKey)
    push_to_server(user.name,"preSignPubKey.txt",user.preSignPubKey)
    push_to_server(user.name,"SignSPKeyPub1.txt",user.SignSPKPub[0])
    push_to_server(user.name,"SignSPKeyPub2.txt",user.SignSPKPub[1])
    for i in range(len(user.otPubKey)):
        push_to_server(user.name,"otPubKey"+str(i)+".txt",user.otPubKey[i])


def get_user_bundle(username):
    bundle = Bundle()
    bundle.idPubKey = fetch_from_server(username,"idPubKey.txt")
    bundle.preSignPubKey = fetch_from_server(username,"preSignPubKey.txt")
    bundle.SignSPKPub = [0]*2
    bundle.SignSPKPub[0] = fetch_from_server(username,"SignSPKeyPub1.txt")
    bundle.SignSPKPub[1] = fetch_from_server(username,"SignSPKeyPub2.txt")
    bundle.n = random.randrange(MAX_OTPK)
    bundle.otPKn = fetch_from_server(username,"otPubKey"+str(bundle.n)+".txt")
    return bundle

def get_x3dh_info(username):
    idPubK = fetch_from_server(username,"idPubKey.txt")
    EphPubK = fetch_from_server(username,"EphPubKey.txt")
    n = fetch_from_server(username,"n.txt")
    remove_from_server(username,"EphPubKey.txt")
    remove_from_server(username,"n.txt")
    return idPubK, EphPubK, n

def get_user_signParam(username):
    p = fetch_from_server(username,"PARAMSignPubKey_P.txt")
    q = fetch_from_server(username,"PARAMSignPubKey_Q.txt")
    g = fetch_from_server(username,"PARAMSignPubKey_G.txt")
    y = fetch_from_server(username,"PARAMSignPubKey_Y.txt")
    return p,q,g,y

def establish_session(receiverName):
    receiverBundle=get_user_bundle(receiverName)
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

def x3dh_sender(sender, receiverName):
    receiverBundle, EphPrivK, EphPubK = establish_session(receiverName)
    
    p,q,g,y = get_user_signParam(receiverName) #Verifie la signature de la clé pré-signé publique
    if verifDSA(int(receiverBundle.SignSPKPub[0]),int(receiverBundle.SignSPKPub[1]),int(p),int(q),int(g),int(y),receiverBundle.preSignPubKey)==False:
        quit()
    
    DH1 = DH(sender.idPrivKey,receiverBundle.preSignPubKey)
    DH2 = DH(EphPrivK,receiverBundle.idPubKey)
    DH3 = DH(EphPrivK,receiverBundle.preSignPubKey)
    DH4 = DH(EphPrivK,receiverBundle.otPKn)
    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    SK = create_sha256_signature(DHf,"INIT")
    sender.SK=SK
    push_to_server(sender.name,"EphPubKey.txt",EphPubK)
    push_to_server(sender.name,"n.txt",receiverBundle.n)
    del DH1, DH2, DH3, DH4, DHf, receiverBundle, EphPrivK, EphPubK


def x3dh_receiver(receiver, senderName):
    sender_idPubK, sender_EphPubK, n = get_x3dh_info(senderName)
    DH1 = DH(receiver.preSignPrivKey, sender_idPubK)
    DH2 = DH(receiver.idPrivKey, sender_EphPubK)
    DH3 = DH(receiver.preSignPrivKey, sender_EphPubK)
    DH4 = DH(receiver.otPrivKey[int(n)],sender_EphPubK)
    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    SK = create_sha256_signature(DHf,"INIT")
    receiver.SK=SK
    #regenere OneTimeKey utilisee
    receiver.otPrivKey[int(n)], receiver.otPubKey[int(n)]=gen_key_pair()
    del DH1, DH2, DH3, DH4, DHf, sender_EphPubK, sender_idPubK, n



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
    push_to_server(user.name,"RPubKey.txt",user.RPubKey)


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
x3dh_sender(bob,alice.name)

x3dh_receiver(alice,bob.name)

#MAIN INIT DOUBLE RATCHET
init_ratchets(alice,1)
init_ratchets(bob,2)


def sendKey(sender,receiverName):
    sender.RPrivKey, sender.RPubKey = gen_key_pair()
    push_to_server(sender.name,"RPubKey.txt",sender.RPubKey)
    receiverPubKey=fetch_from_server(receiverName,"RPubKey.txt")
    RDH=DH(sender.RPrivKey,receiverPubKey)
    sender.sendRatchet.chainKey=turn_ratchet_DH(sender.rootRatchet,RDH)
    messageKey=turn_ratchet(sender.sendRatchet)
    return messageKey


def receiveKey(receiver,senderName):
    senderPubKey=fetch_from_server(senderName,"RPubKey.txt")
    RDH=DH(receiver.RPrivKey,senderPubKey)
    receiver.recvRatchet.chainKey=turn_ratchet_DH(receiver.rootRatchet,RDH)
    messageKey=turn_ratchet(receiver.recvRatchet)
    receiver.RPrivKey, receiver.RPubKey = gen_key_pair()
    push_to_server(receiver.name,"RPubKey.txt",receiver.RPubKey)
    return messageKey

def sendMessage(sender,receiverName,message):
    #recup clé d'envoi
    k=string_to_binary(sendKey(sender,receiverName))
    #encoder message
    

def receiveMessage(receiver,senderName,enc_msg):
    #recup clé de reception
    k=string_to_binary(receiveKey(receiver,senderName))
    #decoder enc_msg
    


def sendFile(sender,receiverName,fileName):
    BLOCK_SIZE = 64
    ROUNDS = 8

    #recup clé d'envoi
    k=string_to_binary(sendKey(sender,receiverName))
    #k=512 bits
    #0-256 : key
    #256-320 : iV

    #récupère le message (fichier) à chiffrer
    msg=fetch_from_server(sender.name,fileName)
    sign=create_sha256_signature(k[320:512],msg)
    #convertion du message en binaire
    msg_bin=string_to_binary(msg)
    msg_bin=padding(msg_bin,BLOCK_SIZE)


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
    push_to_server(sender.name,sender.name+"_to_"+receiverName+".txt",binary_to_hexa(enc_string)[2:])
    push_to_server(sender.name,"Sign"+sender.name+"_to_"+receiverName+".txt",sign)


def ReceiveFile(receiver,senderName):
    BLOCK_SIZE = 64
    ROUNDS = 8

    #recup clé de reception
    k=string_to_binary(receiveKey(receiver,senderName))
    sub_key=split_to_blocks(k[0:BLOCK_SIZE*ROUNDS//2],BLOCK_SIZE//2)
    #recup du chiffré
    enc_msg=fetch_from_server(senderName,senderName+"_to_"+receiver.name+".txt")
    remove_from_server(senderName,senderName+"_to_"+receiver.name+".txt")
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

    msg=binary_to_string(split_to_blocks(dec_string, 8)).rstrip('\x00')
    sign2=create_sha256_signature(k[320:512],msg)
    sign=fetch_from_server(senderName,"Sign"+senderName+"_to_"+receiver.name+".txt")
    remove_from_server(senderName,"Sign"+senderName+"_to_"+receiver.name+".txt")
    if sign!=sign2:
        print("Erreur de transmission")
    else:
        push_to_server(receiver.name,"receiveFile.txt",msg)
    

a=sendFile(alice,bob.name,"sendFile.txt")
b=ReceiveFile(bob,alice.name)






