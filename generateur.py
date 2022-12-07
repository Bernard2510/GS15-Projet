p=7

for i in range(1,p):
    j=1
    res=i
    while res!=1:
        res=res*i%p
        #print(res)
        j=j+1
    print("l'ordre de "+str(i)+" est "+str(j))
    if(j==p-1):
        print(str(i)+" est générateur")
    else:
        print(str(i)+" n'est pas générateur")
    