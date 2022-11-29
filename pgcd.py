def quotient(a,b):
    return a // b

def reste(a,b):
    return a % b


def pgcd(a,b):
    r0=a
    r1=b
    q=0
    r2=1

    while(r2!=0):
        q=quotient(r0,r1)
        r2=reste(r0,r1)
        r0=r1
        r1=r2

    return r0

print(pgcd(235,121))

