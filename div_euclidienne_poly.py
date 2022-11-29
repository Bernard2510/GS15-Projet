A = [0,0,1,1,0,1]
B = [1,1]


def div_poly_R(A,B):

    Q=[0]*len(A)
    R=A
    degR=len(A)-1
    degB=len(B)-1

    while(len(R)!=0 and degR>=degB):
        Q[degR-degB]=A[degR]/B[degB]
        for i in range(len(B)):
            ind=i+(degR-degB)
            R[ind]=R[ind]-A[degR]/B[degB]*B[i]
        degR=degR-1
    
    print(Q)
    print(R)


div_poly_R(A,B)
#[1,X,X^2,X^3,...,X^n]