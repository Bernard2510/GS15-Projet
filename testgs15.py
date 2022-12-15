import random
import hashlib
import secrets
from random import randrange
import gmpy2


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
        nombreAlea = secrets.randbits(longueur)   #revoir génération nombre aléa 
    
    prime=nombreAlea
    #print("prime :",prime)
   
    return prime

def genkeyDSA(L,N): #a revoir algo trop long à process
    L=2048
    N=256

    #q = gen_prime(N) #256 ----- génération safe prime trop long à revoir
    p = gen_prime(L) #2048
    k=2
    inverse=pow(k,-1,p)
    q=((p-1)*inverse)%p
    while rabin_miller(q,8)==False:
        p=gen_prime(L)
        print("q :",q)
        print("inv: ",inverse)
    print("q",q)

    h = randrange(1,p-1)
    g = pow(h,k)%p
    while g<1:
            h = randrange(1,p-1)
            print(h)
    x = randrange(0,q)
    y = pow(g,x)%p

    return p,q,g,y,x
    #p,q,g,y = clé publique et x = clé privé, h est le hache du message

def signDSA(p,q): #Revoir hashmac et génération nombre générateur

    #Etape génération de clés (test on peut enlever ça plus tard)

    p = 1506572662435835448206540536031379484669650426409962965967764867948566111612398653915948276446284788037196198309358444041869900660603303773772722715218694155668242069152996254382089112244024895364179103373870814981436349849818333944086457677059714293428172756425356127973894364549935086073686346060820929763377857753992750732440821666350636185516478482752355487268718942165387717000533340517305952164963658466967545237797103149045087647131708785110600581378244187835869952535739057041457528900489352835966924838981018602678294420358735928142423251104310022642038999912779870480452399487433694544042750774643900021599 #2068  #à générer avec l'algorithme au dessus
    print(rabin_miller(p,25))
    q = 1506572662435835448206540536031379484669650426409962965967764867948566111612398653915948276446284788037196198309358444041869900660603303773772722715218694155668242069152996254382089112244024895364179103373870814981436349849818333944086457677059714293428172756425356127973894364549935086073686346060820929763377857753992750732440821666350636185516478482752355487268718942165387717000533340517305952164963658466967545237797103149045087647131708785110600581378244187835869952535739057041457528900489352835966924838981018602678294420358735928142423251104310022642038999912779870480452399487433694544042750774643900021599//2 #256   #à générer avec l'algorithme au dessus
    print(rabin_miller(q,25))
    k = 2
    if(p-1==k*q):
        print("good")
    h = randrange(1,p-1)
    g = pow(h,k)%p
    while g<1:
            h = randrange(1,p-1)
            print(h)
    x = randrange(0,q) #clé privée
    y = pow(g,x,p)

    print("p:",p)
    print("q:",q)
    print("g:",g)
    print("y:",y)   #clé publique

    #Etape de signature
    s = randrange(1,q)
    s1 = pow(g,s)%p%q
    hash = int(hashlib.sha1(b"123456").hexdigest(),16)
    s2 = (hash%q+s1*x)*pow(s,-1,q)%q #changer 123456 par variable

    while (s1==0 & s2==0):
        s = randrange(2,q-1)
        s1 = pow(g,s,p)%q
        s2 = (hash%q+s1*x)*pow(s,-1,q)%q

    print("s :",s)
    print("s1: ",s1)
    print("s2 :",s2)

    #verification signature
    w = pow(s2,-1,q)
    print(hash)
    u1 = (hash*w)%q
    u2 = (s1*w)%q
    v= (pow(g,u1,p)*pow(y,u2,p)%p)%q
    print("w: ",w)
    print("u1 :",u1)
    print("u2 :",u2)
    print("v: ",v)

    return s1,s2,hash

def verifDSA(s1,s2,p,q,g,y,hash):
   
    if (s1<0 | s1>q) & (s2<0 & s2>q):
        print("erreur")
        return False
    
    w = pow(s2,-1,q)
    u1 = (hash*w)%q
    u2 = (s1*w)%q
    v= (pow(g,u1)*pow(y,u2)%p)%q
    print("v: ",v)

    return True

#signDSA(0,"123456")


#Message Key = HMAC-SHA256(Chain Key, 0x01).
#Chain Key = HMAC-SHA256(Chain Key, 0x02)
# print(hmac_sha256(1,1))

def gensafeprime():
    
    while True:
        p = gen_prime(2048)
        print("test")
        if gmpy2.is_prime((p-1)//2)==True:
            print("p : ",p)
            return p


