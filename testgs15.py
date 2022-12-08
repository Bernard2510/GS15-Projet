import random
import hashlib
import secrets
from random import randrange

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


# def signRSA(priv_key,M):

#     p=random_prime() #ou fixe ?
#     q=random_prime()
#     n=p*q

#     while (n%priv_key==0): #ou verifer premier entre eux
#         p=random_prime()
#         q=random_prime()
#         n=p*q

#     S=M**priv_key % n
#     return S

# def initRSAkey():
#     return 

def quotient(a,b):
    return a // b

def reste(a,b):
    return a % b

def bezout(a,b):
    r0=a
    r1=b
    q=0
    r2=1

    x0=1
    x1=0
    y0=0
    y1=1

    n=0

    while(r2!=0):
        q=quotient(r0,r1)
        r2=reste(r0,r1)
        r0=r1
        r1=r2

        x = q * x1 + x0
        x0 = x1
        x1 = x

        y = q * y1 + y0
        y0 = y1
        y1 = y

        n=n+1

    x = x0 * (-1)**n
    y = y0 * (-1)**(n+1)
    #print("pgcd : ", r0)
    #print("n : ", n)
    #print("x : ", x)
    #print("y : ", y)
    inverse=x%b
    print("inverse : ", x % b)
    return inverse



def rabin_miller(n,k): #Vérifie si n est un nombre premier, k nombre itérations de l'algo
    if n==2 or n==3:
        return True
    if n%2==0:
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
    
    while rabin_miller(nombreAlea,25)==False:
        nombreAlea = secrets.randbits(longueur)   #revoir génération nombre aléa 
    
    prime=nombreAlea
    print("prime :",prime)
   
    return prime

def genkeyDSA(L,N):
    L=2068
    N=256

    #q = gen_prime(N) #256
    p = gen_prime(L) #2068
    k=2
    inverse=pow(k,-1,p)
    q=((p-1)*inverse)%p
    while rabin_miller(q,8)==False:
        p=gen_prime(L)
        print("q :",q)
        print("inv: ",inverse)
    print("q",q)
    return q
genkeyDSA(2068,256)

def signDSA(priv_key,M):
    return s1,s2

#Message Key = HMAC-SHA256(Chain Key, 0x01).
#Chain Key = HMAC-SHA256(Chain Key, 0x02)
# print(hmac_sha256(1,1))

