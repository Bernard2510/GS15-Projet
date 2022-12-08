import os
import random

class Utilisateur:

    def __init__(self,username):
        self.name = username; #nom de l'utilisateur
        self.idPrivKey = "" #ID clé privée
        self.idPubKey = "" #ID clé publique
        self.preSignPubKey = "" #clé publique présignée
        self.preSignPrivKey = "" #clé privée présignée
        self.otPrivKey = [] #liste de clés one time session privée
        self.otPubKey = [] #liste de clés one time session privée

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
    push_to_server(user.name,"idPubKey",user.idPrivKey)
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

def x3dh_sender(sender, receiver):
    receiverBundle, EphPrivK, EphPubK = establish_session(receiver)
    #verif signature
    DH1 = DH(sender.idPrivKey,receiverBundle.preSignPubKey)
    DH2 = DH(EphPrivK,receiverBundle.idPubKey)
    DH3 = DH(EphPrivK,receiverBundle.preSignPubKey)
    DH4 = DH(EphPrivK,receiverBundle.otPKn)

    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    print(DHf)
    #SK = 
    #add SK a l'utilisateur sender
    #supp DH1, 2, 3, 4 et EphPrivK, EphPubK
    x3dh_receiver(sender.idPubKey, EphPubK, receiverBundle.n, receiver) 

def x3dh_receiver(sender_idPubK, sender_EphPubK, n, receiver):
    DH1 = DH(receiver.preSignPrivKey, sender_idPubK)
    DH2 = DH(receiver.idPrivKey, sender_EphPubK)
    DH3 = DH(receiver.preSignPrivKey, sender_EphPubK)
    DH4 = DH(receiver.otPrivKey[n],sender_EphPubK)
    DHf = str(DH1)+""+str(DH2)+""+str(DH3)+""+str(DH4)
    print("--")
    print(DHf)
    #SK = 
    #add SK a l'utilisateur receiver
    #supp DH1, 2, 3, 4 et EphPrivK, EphPubK




MAX_OTPK=5
alice=Utilisateur("alice")
generate_bundle(alice)
publish_bundle(alice)

bob=Utilisateur("bob")
generate_bundle(bob)
publish_bundle(bob)
x3dh_sender(bob,alice)

