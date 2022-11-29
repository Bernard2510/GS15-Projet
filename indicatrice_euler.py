def dec(N):
    res=[]
    d=2
    while N%d==0:
        res.append(d)
        q=int(N/d)
        N=q

    d=3
    while d<=N:
            while N%d==0:
                res.append(d)
                q=int(N/d)
                N=q

            d=d+2

    return res


def fonc_ind_euler(d):
    i=0
    res=1
    while i<len(d):
        occ=d.count(d[i])
        res = res * (d[i]**(occ-1))*(d[i]-1)
        i=i+occ
    return res

n=48
print("decomposition en facteurs premiers : ", dec(n))
print("Fonction indicatrice d'Euler : ",fonc_ind_euler(dec(n)))
