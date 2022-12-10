
from math import sqrt
from random import randrange

def eratosthene(n):
    if n==2:
        return True
    d=2
    r=n%d
    if r == 0:
        return False
    d=3
    while d<= sqrt(n):
        r=n%d
        if r==0:
            return False
        d=d+2
    return True



def fermat(n,k):
    """
    k nb de fois que le test est effectue
    pow(a,k,n-1) remplace a^k mod(n-1)
    randrange(2,n-1) permet de tirer au hasard un nombre a compris entre 2 et n-1
    """
    res=True
    for i in range(k):
        a = randrange(2,n-1)
        if pow(a,k,n-1)!=1:
            res = False
    return res


def rabin_miller(n,k):
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


#print("Eratosthene : ",eratosthene(5))
#print("Fermat : ",fermat(5,2))
print("Rabin-Miller : ",rabin_miller(169889568463,25))

"""
revoir fermat ex 1999
+ ne marche pas avec 3 a cause de randrange
voir avec modulo

tout voir chiffre inf a 4
"""

"""
https://www.lama.univ-savoie.fr/mediawiki/index.php/Algorithmes_probabilistes/d%C3%A9terministes_pour_tester_la_primalit%C3%A9_d%27un_entier#:~:text=Le%20Crible%20d'%C3%89ratosth%C3%A8ne,-Son%20fonctionnement&text=et%20v%C3%A9rifie%20la%20condition%20suivante,D%20%2C%20alors%20N%20est%20premier.
"""