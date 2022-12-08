import random
import hashlib

class Utilisateur:

    def __init__(self,username):
        self.name = username; #nom de l'utilisateur
        self.idPrivK = "" #ID clé privée
        self.idPubKey = "" #ID clé publique
        self.preSignPubKey = "" #clé publique présignée
        self.preSignPrivKey = "" #clé privée présignée
        self.otPK = [] #liste de clés one time session



def randomNum(bit): #xorshift a revoir
    blocBit = bit
    w = random.getrandbits(blocBit)
    z = random.getrandbits(blocBit)
    y = random.getrandbits(blocBit)
    x = random.getrandbits(blocBit)

    t = x^(x<<15)
    u = w^(w>>22)
    O = u^(t^(t>>4))
    return O

#abricot= Utilisateur("erere")
#print(abricot.age,abricot.name)


#def sha256(data):
#    return sha

def concat(x,y):
    c_x=str(x)
    c_y=str(y)
    return (int(c_x+c_y))

def hmac_sha256(chainkey,data):
    ipad=hex(0x36)
    opad=hex(0x5c)
    i_key_pad=chainkey^int(ipad, base=16)
    o_key_pad=chainkey^int(opad, base=16)

    hash_sum_1=hashlib.sha256(str(concat(i_key_pad,data)).encode('ASCII')).hexdigest() #note : implementer sha256
    hash_sum_2=hashlib.sha256(str(concat(o_key_pad,int(hash_sum_1, base=16))).encode('ASCII')).hexdigest()

    #retour cle de com (pour le chiffrement)
    #retour cle chaine pour la prochaine iteration du hmac
    return hash_sum_2


#hmac_sha256(1,1)
# a = 123456789
# print(a)
# m = hashlib.sha256(str(a).encode('ASCII')).hexdigest()
# print(m)


def signRSA(priv_key,M):

    p=random_prime() #ou fixe ?
    q=random_prime()
    n=p*q

    while (n%priv_key==0): #ou verifer premier entre eux
        p=random_prime()
        q=random_prime()
        n=p*q

    S=M**priv_key % n
    return S

def initRSAkey():
    return 
#Message Key = HMAC-SHA256(Chain Key, 0x01).
#Chain Key = HMAC-SHA256(Chain Key, 0x02)
print(hmac_sha256(1,1))
