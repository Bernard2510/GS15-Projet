def sign_rsa(priv_key,M):

    p=random_prime() #ou fixe ?
    q=random_prime()
    n=p*q

    while (n%priv_key==0): #ou verifer premier entre eux
        p=random_prime()
        q=random_prime()
        n=p*q

    S=M**priv_key % n
    return S


def verify_rsa(pub_key,S,M,n):
    M1 = (S**pub_key) % n
    if (M1==M):
        return True
    else:
        return False
