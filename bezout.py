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
    print("pgcd : ", r0)
    print("n : ", n)
    print("x : ", x)
    print("y : ", y)

    print("inverse : ", x % b)


bezout(8,11)


"""
Identité de Bezout = algo d'Euclide etendu
a * x + y * v = PGCD(a,b)

inverse
a*x = 1 - ym
donc
inverse = x mod b
"""