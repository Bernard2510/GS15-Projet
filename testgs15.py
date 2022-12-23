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
    #print(prime.bit_length())
    #print("prime :",prime)
   
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
            g = gen_elementgen(p) 
            IDpriv = secrets.randbits(2048)
            IDpub =pow(g,IDpriv,p)
            return IDpriv, IDpub
        if choix =="2":
            print("Vous avez choisi de générer un nouveau couple de clés.")
            p = gen_safeprime()
            g = gen_elementgen(p)
            IDpriv = secrets.randbits(2048)
            IDpub =pow(g,IDpriv,p)
            return IDpriv, IDpub


def genkeyDSA(IDpriv): #On génère p, q, k tel que p-1=k*q avec p et q premier cependant pour faciliter les calculs on a pris k=2 et on se retrouve sur un problème d'existence d'un élément fortement premier

    x=IDpriv
    print("Génération des clés identités :")
    choix = ""
    
    while True:
        choix = input("Ecrivez (1) pour laisser les clés par défaut pour démonstration, écrivez (2) pour générer de nouvelles clés.\n")
        if choix=="1":
            print("Vous avez choisi les paramètres par défaut.")
            p = 25275318963339501038904470567825138989060892737850578690358537231136482965510643268892699094003169567172687775542517182268676187800707418045999665720755350062432181515161865056719921816903657186723467176816222260278298693819846695171242366160403294103543366955861293307465384792437392827099649684774492739181210624829503989085343109951316675541243576941969934847161707999715528313403784352129647086251514324416816696320411947050545430487590651368224606778237019311251049555852486530156354038756890813023254935463876763698020345356943388292880124193038709698210894884428260734105918833601964994252759024480315396597759
            break
        if choix=="2":
            print("Vous avez choisi de générer une nouvelle clé.")
            p = gen_safeprime()
            break

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
        print("erreur")
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

# IDpriv, IDpub = gen_IDKey()
# p,q,g,y= genkeyDSA(IDpriv)
# M="12345"
# M2="1234"
# s1,s2 = signDSA(p,q,g,IDpriv,M)
# verifDSA(s1,s2,p,q,g,y,M)

def vernam_chiffrement(message,key):

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

def vernam_dechiffrement(msg_chiffre,key):

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


key ="KEJXEZAZEZzeaeazxzae325465ra5464razea"

encrypte = vernam_chiffrement("Salut comment ca va? a123^^ez%°+°°32///..EZREMRMLEZRALXMZEA",key)
print(encrypte)
print(vernam_dechiffrement(encrypte,key))