def expo(a,e,m):
    res = 1
    while(e>0):
        if(e%2 == 1):
            res = (res*a) % m
        e = e//2
        a = (a*a) % m
    return res

print(expo(333,995,997))

"""
a^e mod m
"""