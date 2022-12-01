import random

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

def xor(x, y):
    return 

def sha256(data):
    return sha

def concat(x,y):
    return

def hmac_sha256(chainkey,data):
    ipad=hex(0x36)
    opad=hex(0x5c)
    i_key_pad=xor(chainkey,ipad)
    o_key_pad=xor(chainkey,opad)
    hash_sum_1=sha256(concat(i_key_pad,data))
    hash_sum_2=sha256(concat(o_key_pad,hash_sum_1))

    return hash_sum_2


#hmac_sha256(1,1)