import os
import random
from random import randrange
import hashlib
from math import ceil
import secrets
import gmpy2

import hmac
import binascii

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

        self.rootRatchet = SymmRatchet #ratchet racine
        self.sendRatchet = SymmRatchet #ratchet d'envoi
        self.recvRatchet = SymmRatchet #ratchet de reception

        self.RPrivKey = ""  #double ratchet clé privée
        self.RPubKey = ""   #double ratchet clé publique



class Bundle:

    def __init__(self):
        self.idPubKey = "" #ID clé publique
        self.preSignPubKey = "" #clé publique présignée
        self.SignSPKPub = [] #signature de la clé publique présignée
        self.otPKn = "" #liste de clés one time session
        self.n = "" #numéro one time key utilisee


class SymmRatchet:

    def __init__(self, key):
        self.chainKey = key #ratchet chainkey

"""
===============================================================
Fonction intéraction avec serveur
(envoi/suppression de fichier)
===============================================================
"""

def push_to_server(username,name,content): #crée un fichier sur le serveur
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)

    #si le repertoire du serveur n'existe pas il est crée
    try:
        os.mkdir(server_path)
    except OSError:
        pass

    #si le repertoire de l'utilisateur n'existe pas il est crée
    try:
        os.mkdir(user_path)
    except OSError:
        pass
    
    #un fichier <filename> est crée dans le repertoire server/<username>
    #contenant le donnée à publier
    #le nom du fichier correpond au nom de la donnée
    #si un fichier du meme nom existe deja il est remplacé
    filename = name
    file_path=os.path.join(user_path,filename)
    with open(file_path,mode='w') as file:
        file.writelines(str(content))
        


def fetch_from_server(username,name): #recupère le contenu d'un fichier sur le serveur
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name
    file_path=os.path.join(user_path,filename)
    #on recupere le contenu du fichier server/<username>/<filename>
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        string=""
        for l in lines:
            string=string+str(l)
        return string

def remove_from_server(username,filename): #supprime un fichier sur le serveur
    #on supprime le fichier server/<username>/<filename>
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
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


def gen_ValueParam(): #Permet de générer les valeurs p (fortement premier) et g (élement générateur d'un corps cyclique) utilisés tout au long de l'échange

    print("Génération des valeurs identités :")
    choix = ""
    
    while True:
        choix = input("Ecrivez (1) pour laisser les valeurs identités par défaut pour démonstration, écrivez (2) pour générer de nouvelles valeurs identités.\n")
        if choix =="1":
            print("Vous avez choisi les paramètres par défaut.")
            p = 25275318963339501038904470567825138989060892737850578690358537231136482965510643268892699094003169567172687775542517182268676187800707418045999665720755350062432181515161865056719921816903657186723467176816222260278298693819846695171242366160403294103543366955861293307465384792437392827099649684774492739181210624829503989085343109951316675541243576941969934847161707999715528313403784352129647086251514324416816696320411947050545430487590651368224606778237019311251049555852486530156354038756890813023254935463876763698020345356943388292880124193038709698210894884428260734105918833601964994252759024480315396597759 #2048  #à générer avec l'algorithme au dessus
            push_to_server("","Value_P.txt",p)
            print("p: ",p)
            g = gen_elementgen(p) 
            push_to_server("","Value_G.txt",g)
            break
        if choix =="2":
            print("Vous avez choisi de générer un nouveau couple de valeurs identités.")
            p = gen_safeprime()
            push_to_server("","Value_P.txt",p)
            g = gen_elementgen(p)
            push_to_server("","Value_G.txt",g)
            break

def gen_IDkey(): #Permet de générer les clés identités.

    print("Génération des clés identités.")

    p=int(fetch_from_server("","Value_P.txt"))
    g=int(fetch_from_server("","Value_G.txt"))
    IDpriv = secrets.randbits(2048)
    IDpub =pow(g,IDpriv,p)
    return IDpriv, IDpub

def gen_key_pair():
    p = int(fetch_from_server("","Value_P.txt"))
    g = int(fetch_from_server("","Value_G.txt"))
    priv = secrets.randbits(512)
    pub = pow(g,priv,p)
    return priv, pub

def gen_signKey(username,key,IDPrivKey):
    genkeyDSA(username,IDPrivKey)
    p = fetch_from_server("","Value_P.txt")
    q = fetch_from_server(username,"PARAMSignPubKey_Q.txt")
    g = fetch_from_server(username,"PARAMSignPubKey_G.txt")
    s1,s2 = signDSA(int(p),int(q),int(g),int(IDPrivKey),str(key)) #ici key représente le message dans la fonction DSA originale
    return s1,s2

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
===============================================================
Chiffrement de flux Vernam 
(chiffrement et déchiffrement)
===============================================================
"""

def vernam_chiffrement(message,key): #Prend en paramètres un message str et la clé (ici la clé SK partagée)

    #Fonctionnement : Comme la clé est d'une taille fixe, on va la multiplier et la formater afin qu'elle fasse la même taille que le message pour faire un chiffrement XOR vernam avec.

    message_length=len(message)
    key_length=len(key)
    nbFois=message_length//key_length
    nbReste=message_length%key_length
    keyFormate=key*nbFois+key[:nbReste]

    msg_chiffre=""
    i=0
    for char in message:
        msg_chiffre=msg_chiffre+ chr(ord(char)^ ord(keyFormate[i]))
        i+=1
    return msg_chiffre

def vernam_dechiffrement(msg_chiffre,key): #Exactement pareil que le chiffrement mais avec nom différent pour se retrouver.

    message_length=len(msg_chiffre)
    key_length=len(key)
    nbFois=message_length//key_length
    nbReste=message_length%key_length
    keyFormate=key*nbFois+key[:nbReste]

    msg_clair=""
    i=0
    for char in msg_chiffre:
        msg_clair=msg_clair+ chr(ord(char)^ ord(keyFormate[i]))
        i+=1
    return msg_clair


"""
===============================================================
===============================================================
"""


"""
===============================================================
Chiffrement de bloc Feistel 
(chiffrement et déchiffrement)
===============================================================
"""
def binary_to_hexa(bits): #convertie un suite binaire en valeur hexadecimal
    return hex(int(bits, 2))

def hexa_to_binary(hex,block_size): #convertie une valeur hexadecimal en suite binaire
    hex=bin(int(hex, 16))[2:]
    pad=ceil(len(hex)/block_size)*block_size
    return hex.zfill(pad)

def string_to_binary(string): #convertie une chaine de caractere en suite binaire
    str = ''.join('{:08b}'.format(ord(c)) for c in string)
    return str

def binary_to_string(bits): #convertie une suite binaire en chaine de caractere
    return ''.join([chr(int(x, 2)) for x in bits])

def padding(bin_string,block_size): #ajoute des '0' à la fin d'une suite binaire
    #on ajoute autant de '0' que necessaire afin que la taille de la suite binaire soit un multiple de la taille de bloc choisie
    return bin_string.ljust(block_size * ceil(len(bin_string)/block_size), '0')

def split_to_blocks(msg, block_size): #divise une suite binaire en bloc de taille choisie
    nb_block = ceil(len(msg)/block_size)
    res=[""]*nb_block
    for i in range(nb_block):
        res[i]=msg[i*block_size:(i+1)*block_size]
    return res

#Fonction de feistel
def xor(K,D): #xor de deux elements binaires
    return int(K,base=2)^int(D,base=2)

def feistel_encrypt(data,key,rounds): #chiffrement par tournée de Feistel
    #la suite binaire a chiffree est divisee en deux blocs (bloc de droite et bloc de gauche)
    G0=data[:int(len(data)/2)]
    D0=data[int(len(data)/2):]
    T=rounds
    #on applique T tournées de feistel 
    #pour chaque tournée Gi+1 prend la valeur de Di
    #Di+1 prend la valeur de Gi xoré avec le resultat du xor (fonction de Feistel) de Ki et Di
    for i in range(T):
        G1=D0
        D1Dec=int(G0,base=2)^xor(key[i],D0)
        D1=bin(D1Dec)[2:].zfill(len(G0))

        G0=G1
        D0=D1  
    return G1+""+D1
    
def feistel_decrypt(data,key,rounds): #déchiffrement par tournée de Feistel
    #la suite binaire a dechiffree est divisee en deux blocs (bloc de droite et bloc de gauche)
    G1=data[:int(len(data)/2)]
    D1=data[int(len(data)/2):]
    T=rounds
    #on applique T tournées de feistel 
    #Gi-1 prend la valeur de Di xoré avec le resultat du xor (fonction de Feistel) de Ki et Gi
    #pour chaque tournée Di-1 prend la valeur de Gi
    for i in range(T):
        G0Dec=int(D1,base=2)^xor(key[7-i],G1)
        G0=bin(G0Dec)[2:].zfill(len(D1))
        D0=G1
        
        G1=G0
        D1=D0
    return G0+""+D0

"""
===============================================================
===============================================================
"""

"""
===============================================================
Initialisation user
(Création des clés et publication sur le serveur)
===============================================================
"""

def generate_bundle(user): #crée les clés d'un utilisateur pour X3DH
    user.idPrivKey, user.idPubKey = gen_IDkey() #génération des clés identitées
    user.preSignPrivKey, user.preSignPubKey = gen_key_pair() #génération des clés pré-signées
    user.otPrivKey = [0]*MAX_OTPK
    user.otPubKey = [0]*MAX_OTPK
    user.SignSPKPub = [0]*2
    user.SignSPKPub[0], user.SignSPKPub[1]=gen_signKey(user.name,user.preSignPubKey,user.idPrivKey) #calcul de la signature de la clé publique pré-signée par la clé privée d'identité
    for i in range(MAX_OTPK):
        user.otPrivKey[i], user.otPubKey[i]=gen_key_pair() #génération des clés à usage unique


def publish_bundle(user): #publie sur le serveur les clés publiques d'un utilisateur
    push_to_server(user.name,"idPubKey.txt",user.idPubKey)
    push_to_server(user.name,"preSignPubKey.txt",user.preSignPubKey)
    push_to_server(user.name,"SignSPKeyPub1.txt",user.SignSPKPub[0])
    push_to_server(user.name,"SignSPKeyPub2.txt",user.SignSPKPub[1])
    for i in range(len(user.otPubKey)):
        push_to_server(user.name,"otPubKey"+str(i)+".txt",user.otPubKey[i])

"""
===============================================================
===============================================================
"""

"""
===============================================================
Diffie-Hellman et HMAC
===============================================================
"""
def DH(a,B):
    p = int(fetch_from_server("","Value_P.txt"))
    return pow(int(B),int(a),p)

def create_sha256_signature(key, message):
    if len(key)%2 != 0:
        key=key+"0"
    byte_key = binascii.unhexlify(key)
    message = message.encode()
    return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()
"""
===============================================================
===============================================================
"""


"""
===============================================================
X3DH
===============================================================
"""

def get_user_bundle(username): #récupère sur le serveur les clés publiques d'un utilisateur nécessaire à un échange de clé X3DH
    bundle = Bundle()
    bundle.idPubKey = fetch_from_server(username,"idPubKey.txt")
    bundle.preSignPubKey = fetch_from_server(username,"preSignPubKey.txt")
    bundle.SignSPKPub = [0]*2
    bundle.SignSPKPub[0] = fetch_from_server(username,"SignSPKeyPub1.txt")
    bundle.SignSPKPub[1] = fetch_from_server(username,"SignSPKeyPub2.txt")
    bundle.n = random.randrange(MAX_OTPK)
    bundle.otPKn = fetch_from_server(username,"otPubKey"+str(bundle.n)+".txt") #une clé à usage unique est choisie au hasard
    return bundle

def get_x3dh_info(username): #récupère sur le serveur les clés publiques et les informations nécessaires à la finalisation par le 2nd utilisateur du protocol d'échange de clé X3DH
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

def establish_session(receiverName): #établissement du protocole d'échange de clé X3DH
    #récupère le lot de clé de l'utilisateur avec qui initier un échange de clé X3DH
    receiverBundle=get_user_bundle(receiverName)
    #génration des clés éphémères
    EphPrivK,EphPubK = gen_key_pair()
    return receiverBundle, EphPrivK, EphPubK

def x3dh_sender(sender, receiverName): #actions effectuées par l'initiateur de l'échange de clé X3DH
    receiverBundle, EphPrivK, EphPubK = establish_session(receiverName)
    
    p,q,g,y = get_user_signParam(receiverName) #Verifie la signature de la clé pré-signé publique
    if verifDSA(int(receiverBundle.SignSPKPub[0]),int(receiverBundle.SignSPKPub[1]),int(p),int(q),int(g),int(y),receiverBundle.preSignPubKey)==False:
        quit()
    
    #calcul des DHs
    DH1 = DH(sender.idPrivKey,receiverBundle.preSignPubKey)
    DH2 = DH(EphPrivK,receiverBundle.idPubKey)
    DH3 = DH(EphPrivK,receiverBundle.preSignPubKey)
    DH4 = DH(EphPrivK,receiverBundle.otPKn)
    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    #calcul de la clé partagée SK
    SK = create_sha256_signature(DHf,"INIT")
    sender.SK=SK
    print("\nSK "+sender.name+" : ")
    print(SK)
    #publie sur le serveur les éléments nécessaires au 2nd utilisateur pour qu'il puisse également calculer la clé partagée SK
    push_to_server(sender.name,"EphPubKey.txt",EphPubK)
    push_to_server(sender.name,"n.txt",receiverBundle.n)
    del DH1, DH2, DH3, DH4, DHf, receiverBundle, EphPrivK, EphPubK


def x3dh_receiver(receiver, senderName): #actions effectuées par le partenaire de l'échange de clé X3DH
    #récupère les informations nécessaire proveannt de l'initiateur
    sender_idPubK, sender_EphPubK, n = get_x3dh_info(senderName)
    #calcul des DHs
    DH1 = DH(receiver.preSignPrivKey, sender_idPubK)
    DH2 = DH(receiver.idPrivKey, sender_EphPubK)
    DH3 = DH(receiver.preSignPrivKey, sender_EphPubK)
    DH4 = DH(receiver.otPrivKey[int(n)],sender_EphPubK)
    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    SK = create_sha256_signature(DHf,"INIT")
    print("\nSK "+receiver.name+" : ")
    print(SK)
    #calcul de la clé partagée SK
    receiver.SK=SK
    #Genere une nouvelle clé a usage unique pour remplacer celle utilisée
    receiver.otPrivKey[int(n)], receiver.otPubKey[int(n)]=gen_key_pair()
    del DH1, DH2, DH3, DH4, DHf, sender_EphPubK, sender_idPubK, n

"""
===============================================================
===============================================================
"""

"""
===============================================================
Double ratchet
===============================================================
"""
def init_ratchets(user,order): #initialisation des ratchets racine, d'envoi et de réception
    #le ratchet racine est initialisé avec la clé partagée SK (via X3DH)
    user.rootRatchet = SymmRatchet(user.SK)
    # initialise the sending and recving chains
    #le ratchet d'envoi puis de reception sont initialisés (inversement pour le 2nd utilisateurs)
    if order == 1:
        #les ratchets sont initialisés avec la sortie du ratchet racine (en "tournant" le ratchet racine pour chacun)
        user.sendRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
        user.recvRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
    else:
        user.recvRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
        user.sendRatchet = SymmRatchet(turn_ratchet(user.rootRatchet))
    #initialisation des clés utilisées pour calcul de clé partagée via Diffie-Helman dans l'algorithme du double ratchet
    user.RPrivKey, user.RPubKey = gen_key_pair()
    #clé publique publiée sur le serveur
    push_to_server(user.name,"RPubKey.txt",user.RPubKey)


def turn_ratchet(ratchet): #"Tour" de ratchet symétrique
    C1="0x01"
    C2="0x02"
    #Les données sont OxO1 et la clé chainée pour le calcul de la clé de message
    #KDF : HMAC-SHA256
    messageKey = create_sha256_signature(ratchet.chainKey,C1)
    #Les données sont OxO2 et la clé chainé pour le calcul de la nouvelle clé chainée
    #KDF : HMAC-SHA256
    ratchet.chainKey = create_sha256_signature(ratchet.chainKey,C2)
    return messageKey

def turn_ratchet_DH(ratchet,dh): #"Tour" de ratchet symétrique avec clé partagée
    #KDF : HMAC-SHA256
    output = create_sha256_signature(ratchet.chainKey,str(dh))
    #premiere partie correspond à la nouvelle clé chainée
    ratchet.chainKey = output[:32]
    #deuxième partie correspond à la clé de message
    messageKey = output[32:]
    return messageKey

def sendKey(sender,receiverName): #fournie la clé d'envoi
    #mise à jour et publication sur le serveur du nouveau couple de clé
    sender.RPrivKey, sender.RPubKey = gen_key_pair()
    push_to_server(sender.name,"RPubKey.txt",sender.RPubKey)
    #réception depuis le serveur de la clé publique de l'interlocuteur
    receiverPubKey=fetch_from_server(receiverName,"RPubKey.txt")
    #calcul de la clé partagée
    RDH=DH(sender.RPrivKey,receiverPubKey)
    #calcul de la clé de chiffrement via le ratchet d'envoi (et mise à jour de sa clé chainée)
    sender.sendRatchet.chainKey=turn_ratchet_DH(sender.rootRatchet,RDH)
    messageKey=turn_ratchet(sender.sendRatchet)
    print("\n"+sender.name+" send ratchet messageKey : "+messageKey)
    return messageKey

def receiveKey(receiver,senderName): #fournie la clé de reception
    #réception depuis le serveur de la clé publique de l'interlocuteur
    senderPubKey=fetch_from_server(senderName,"RPubKey.txt")
    #calcul de la clé partagée
    RDH=DH(receiver.RPrivKey,senderPubKey)
    #calcul de la clé de déchiffrement via le ratchet de reception (et mise à jour de sa clé chainée)
    receiver.recvRatchet.chainKey=turn_ratchet_DH(receiver.rootRatchet,RDH)
    messageKey=turn_ratchet(receiver.recvRatchet)
    #mise à jour et publication sur le serveur du nouveau couple de clé
    receiver.RPrivKey, receiver.RPubKey = gen_key_pair()
    push_to_server(receiver.name,"RPubKey.txt",receiver.RPubKey)
    print("\n"+receiver.name+" receiver ratchet messageKey : "+messageKey)
    return messageKey
"""
===============================================================
===============================================================
"""

"""
===============================================================
Fonctions utilisateurs (Envoi/Reception de Message/Fichier)
===============================================================
"""
def sendMessage(sender,receiverName,message): #envoi d'un message chiffré (chiffrement de flux)
    #recupération de la clé de chiffrement
    k=string_to_binary(sendKey(sender,receiverName))
    #calcul du HMAC du message a envoyer
    sign=create_sha256_signature(k,message)
    #chiffrement du message
    print(sender.name+" a envoye un message a "+receiverName+" : "+message)
    return vernam_chiffrement(message,k),sign
    

def receiveMessage(receiver,senderName,enc_msg,sign): #reception et déchiffrement d'un message (déchiffrement de flux) 
    #recupération de la clé de déchiffrement
    k=string_to_binary(receiveKey(receiver,senderName))
    #dechiffrement du message
    dec_msg=vernam_dechiffrement(enc_msg,k)
    #calcul du HMAC du message recu
    sign2=create_sha256_signature(k,dec_msg)
    print(receiver.name+" a reçu un message de "+senderName)
    #verification du HMAC
    print("Verification hmac")
    if sign!=sign2:
        print("Erreur de transmission")
    else:
        #reception du message si verification HMAC valide
        print("Message reçu")
        return dec_msg


def sendFile(sender,receiverName,fileName): #envoi d'un fichier chiffré (chiffrement de bloc)
    #taille des blocs et nombre de tournée de Feistel
    BLOCK_SIZE = 64
    ROUNDS = 8

    #recupération de la clé de chiffrement
    k=string_to_binary(sendKey(sender,receiverName))
    #la clé de 512 bits se divise de la facon suivante :
    #0-256 : clé de chiffrement
    #256-320 : IV
    #320-512 : clé HMAC

    #récupèration le message (fichier) à chiffrer
    msg=fetch_from_server(sender.name,fileName)
    #calcul du HMAC du fichier a envoyer
    sign=create_sha256_signature(k[320:512],msg)
    #convertion du message en une suite binaire
    msg_bin=string_to_binary(msg)
    msg_bin=padding(msg_bin,BLOCK_SIZE)

    #IV
    iv_init=k[BLOCK_SIZE*ROUNDS//2:BLOCK_SIZE*(ROUNDS//2+1)]
    iv=iv_init
    #division en bloc du message
    msg_bin_tab=split_to_blocks(msg_bin,BLOCK_SIZE)
    #division en bloc de la clé de chiffrement
    sub_key=split_to_blocks(k[0:BLOCK_SIZE*ROUNDS//2],BLOCK_SIZE//2)
    #Application des tournés de Feistel sur les blocs du message mode CBC
    tab_enc=[""]*len(msg_bin_tab)
    for i in range(len(msg_bin_tab)): #pour chaque bloc du message
        msg_bin_tab[i]=xor(iv,msg_bin_tab[i]) #xor avec l'IV
        msg_bin_tab[i]=bin(msg_bin_tab[i])[2:].zfill(BLOCK_SIZE)
        tab_enc[i]=feistel_encrypt(msg_bin_tab[i],sub_key,ROUNDS) #tournées de Feistel
        iv=tab_enc[i] #IV devient le bloc chiffré précédent

    #envoi du fichier chiffré sur le serveur (chiffré en hexadécimal)
    enc_string=""
    for i in range(len(tab_enc)):
        enc_string=enc_string+tab_enc[i]
    push_to_server(sender.name,sender.name+"_to_"+receiverName+".txt",binary_to_hexa(enc_string)[2:])
    push_to_server(sender.name,"Sign"+sender.name+"_to_"+receiverName+".txt",sign)
    print("\n"+sender.name+" a envoye le fichier "+fileName+" a "+receiverName)
    print("Fichier chiffré (hexa) : "+binary_to_hexa(enc_string)[2:])


def ReceiveFile(receiver,senderName): #envoi d'un fichier chiffré (chiffrement de bloc)
    #taille des blocs et nombre de tournée de Feistel
    BLOCK_SIZE = 64
    ROUNDS = 8

    #recupération de la clé de déchiffrement
    k=string_to_binary(receiveKey(receiver,senderName))
    #la clé de 512 bits se divise de la facon suivante :
    #0-256 : clé de chiffrement
    #256-320 : IV
    #320-512 : clé HMAC

    #récupèration le message (fichier) à déchiffrer
    enc_msg=fetch_from_server(senderName,senderName+"_to_"+receiver.name+".txt")
    remove_from_server(senderName,senderName+"_to_"+receiver.name+".txt")
    #convertion du message chiffré en une suite binaire
    #division en bloc du message
    tab_enc=split_to_blocks(hexa_to_binary(enc_msg,BLOCK_SIZE),BLOCK_SIZE)
    #division en bloc de la clé de déchiffrement
    sub_key=split_to_blocks(k[0:BLOCK_SIZE*ROUNDS//2],BLOCK_SIZE//2)
    #IV
    iv_init=k[BLOCK_SIZE*ROUNDS//2:BLOCK_SIZE*(ROUNDS//2+1)]
    iv=iv_init
    
    #Application des tournés de Feistel sur les blocs du chiffré mode CBC
    dec_string=""
    tab_dec=[""]*len(tab_enc)
    for i in range(len(tab_enc)): #pour chaque bloc du message
        tab_dec[i]=feistel_decrypt(tab_enc[i],sub_key,ROUNDS) #tournées de Feistel
        tab_dec[i]=xor(iv,tab_dec[i]) #xor avec l'IV
        tab_dec[i]=bin(tab_dec[i])[2:].zfill(BLOCK_SIZE)
        iv=tab_enc[i] #IV devient le bloc déchiffré précédent
        dec_string=dec_string+tab_dec[i]

    #suppression du padding
    msg=binary_to_string(split_to_blocks(dec_string, 8)).rstrip('\x00')
    #calcul du HMAC du message déchiffré
    sign2=create_sha256_signature(k[320:512],msg)
    sign=fetch_from_server(senderName,"Sign"+senderName+"_to_"+receiver.name+".txt")
    remove_from_server(senderName,"Sign"+senderName+"_to_"+receiver.name+".txt")
    print(receiver.name+" reçoit un fichier de "+senderName)
    #verification du HMAC
    print("Verification hmac")
    if sign!=sign2:
        print("Erreur de transmission")
    else:
        #reception du message si verification HMAC valide
        push_to_server(receiver.name,"receiveFile.txt",msg)
        print("Fichier reçu : receiveFile.txt")

"""
===============================================================
===============================================================
"""




"""
===============================================================
Main
===============================================================
"""


#MAIN INIT X3DH
MAX_OTPK=5 #nombre de clé à usage unique à générer
gen_ValueParam()
#création de l'utilisateur Alice et de son lot de clé
alice=Utilisateur("alice")
generate_bundle(alice)
publish_bundle(alice)

#création de l'utilisateur Bob et de son lot de clé
bob=Utilisateur("bob")
generate_bundle(bob)
publish_bundle(bob)

#Protocole d'echange de clé X3DH entre Alice et Bob
x3dh_sender(bob,alice.name)
x3dh_receiver(alice,bob.name)

#MAIN INIT DOUBLE RATCHET
#Initialisation des ratchets des utilisateurs Alice et Bob
init_ratchets(alice,1)
init_ratchets(bob,2)


def actionChoice(sender,receiver): #menu choix de l'action à effectuer
    val=False
    while(val==False):
        print("\nQue souhaitez vous faire :")
        choix = input("(1) Envoyer message\n(2) Envoyer fichier\n")
        if choix =="1":
            val=True
            print("Taper votre message (Entrer pour valdier) :")
            message= input(">")
            enc_msg,sign=sendMessage(sender,receiver.name,message)
            print("Message encodé : "+enc_msg)
            reception(receiver,sender.name,"message",enc_msg,sign)
        elif choix =="2":
            val=True
            sendFile(sender,receiver.name,"sendFile.txt")
            reception(receiver,sender.name,"file")



def reception(receiver,senderName,type,enc_msg="",sign=""): #menu reception d'un message/fichier
    val=False
    while(val==False):
        print("\n"+receiver.name+" vous avez reçu un message de "+senderName)
        print("Souhaitez vous l'ouvrir")
        choix = input("(1) Oui\n(2) Non\n")
        if choix =="1":
            val=True
            if(type=="message"):
                msg=receiveMessage(receiver,senderName,enc_msg,sign)
                print("Message decodé : "+msg)
            elif(type=="file"):
                ReceiveFile(receiver,senderName)




while True: #menu principal choix utilisateur
    print("\nBonjour, qui êtes vous :")
    choix = input("(1) Alice\n(2) Bob\n(3) Quitter\n")
    if choix =="1":
        actionChoice(alice,bob)
    elif choix =="2":
        actionChoice(bob,alice)
    elif choix =="3":
        quit()




"""
===============================================================
===============================================================
"""
