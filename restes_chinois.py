def quotient(a,b):
    return a // b

def reste(a,b):
    return a % b


def inverse(a,b):
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

    return(x % b)


def restes_chinois(a,mi):
    M=1
    for i in mi:
        M = M * i
    
    Mi=[0]*len(mi)
    for i in range(len(mi)):
        Mi[i]=int(M/mi[i])

    
    x=0
    for i in range(len(mi)):
        x = x + a[i]*Mi[i]*inverse(Mi[i],mi[i])

    x = x%M
        
    print("x = ",x, " mod ",M)
    return x



x = [2,4,6]
mi = [3,5,7]
restes_chinois(x,mi)

x = [2,5]
mi = [11,7]
restes_chinois(x,mi)
