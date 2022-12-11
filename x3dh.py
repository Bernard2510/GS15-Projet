import os
import random
import hashlib

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
    print(SK)
    print("---")
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
    print(SK)
    receiver.SK=SK
    #supp DH1, 2, 3, 4 et EphPrivK, EphPubK



class SymmRatchet:

    def __init__(self, key):
        self.chainKey = key

    """
    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv
    """


def init_ratchets(user,order):
    # initialise the root chain with the shared key
    user.rootRatchet = SymmRatchet(user.SK)
    # initialise the sending and recving chains
    if order == 1:
        user.sendRatchet = SymmRatchet(turn_ratchet_root(user.rootRatchet,user.rootRatchet.chainKey))
        user.recvRatchet = SymmRatchet(turn_ratchet_root(user.rootRatchet,user.rootRatchet.chainKey))
    else:
        user.recvRatchet = SymmRatchet(turn_ratchet_root(user.rootRatchet,user.rootRatchet.chainKey))
        user.sendRatchet = SymmRatchet(turn_ratchet_root(user.rootRatchet,user.rootRatchet.chainKey))

def turn_ratchet_root(ratchet,key):
    C1="0x01"
    C2="0x02"
    messageKey = create_sha256_signature(key,C1)
    ratchet.chainKey = create_sha256_signature(key,C2)
    return messageKey

def turn_ratchet(ratchet,key,data):
    messageKey = create_sha256_signature(key,data)
    ratchet.chainKey = create_sha256_signature(key,data)
    return messageKey

MAX_OTPK=5
alice=Utilisateur("alice")
generate_bundle(alice)
publish_bundle(alice)

bob=Utilisateur("bob")
generate_bundle(bob)
publish_bundle(bob)
x3dh_sender(bob,alice)

init_ratchets(alice,1)
init_ratchets(bob,2)

print('\nAlice send ratchet:', turn_ratchet_root(alice.sendRatchet, alice.sendRatchet.chainKey))
print('\nBob recv ratchet:', turn_ratchet_root(bob.recvRatchet, bob.recvRatchet.chainKey))
print('\nAlice recv ratchet:', turn_ratchet_root(alice.recvRatchet, alice.recvRatchet.chainKey))
print('\nBob send ratchet:', turn_ratchet_root(bob.sendRatchet, bob.sendRatchet.chainKey))




def RatchetKeyPair(user,receivePubKey=0):
    if (user.RPrivKey=="" and user.RPrubKey==""):
        RPrivK,RPubK = gen_key_pair()
    else:
        DHK=DH(RPrivK, receivePubKey)
    return RPubK, DHK

    #return RPrivK,RPubK
    #send RpubK to Alice


RBPriv, RBPub = gen_key_pair()
RAPriv, RAPub = gen_key_pair()

DHA=DH(RAPriv,RBPub) #envoie message
#bob recoit message
DHB=DH(RBPriv,RAPub)

#print(DHA)
#print(DHB)
print(turn_ratchet(alice.sendRatchet, alice.sendRatchet.chainKey,str(DHA)))
print(turn_ratchet(bob.recvRatchet, bob.recvRatchet.chainKey,str(DHB)))


"""
RB bob genere et envoi

RA, DH(RA,RB) alice genere et envoi, turn sym
DH(RA,RB) bob turn recv

RB', DH(RB',RA) bob send
DH(RA,RB') alice recv

genere et envoi DH
message env
"""


