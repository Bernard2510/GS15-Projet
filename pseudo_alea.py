from secrets import *
from random import randrange

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


def pseudo_alea(n):
    return randbelow((2**n)-1)

a = pseudo_alea(4)
print(a)
print(rabin_miller(a,3))