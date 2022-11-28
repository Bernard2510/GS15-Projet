"""
Alice
"""

IDA = (generate_nb(),genrate_nb()) #taille 2048 bit
PKA =
SigPKA

N=10
OtPKA = [0]*N
for i in range(N):
    OtPKA[i]=(generate_nb(),genrate_nb())

EphA = genrate_nb()

"""
Bob
"""





"""
X3DH
"""
def server_publication(IDpub,SigPKpub,...,OtPK):
    #a remplir

def contact_user(username):
    #choose pre-key
    #supp pre_key server
    return bundle

def DH(priv,pub):


def initialisation_key():
    #Alice
    server_publication()
    #Bob
    server_publication()

def X3DH_Bob():
    alice_bundle=contact_user("alice")
    if(verify_rsa()==True): #siganture pré-clé
        EphB = (generate_nb(),generate_nb())
        DH1 = DH(IDB[0],...)
        DH2 =
        DH3 =
        DH4 =
        SK = KDF() #concat DH1, DH2, DH3,  DH4
        #supp Eph
        #supp DH1, DH2, DH3, DH4
        server_publication(IDB[1]) #cle pub d'id
        server_publication(EphB[1]) #cle pub ephemere
        server_publication(n) #num cle usage unique OtPKnA
    else:
        exit

def X3DH_Alice():
    SK=

def initialisation():
    initialisation_key()
    X3DH_Bob()
    X3DH_Alice
