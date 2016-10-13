#E. Mogammed et al. proposed a blind signature scheme, which did not meet the unforgeability.
#This implementation is insecure!

import random

from Crypto.Util import number
from Crypto.PublicKey import ElGamal
from Crypto import Random

def getRandomCoPrime(p):
    k = random.randint(2, p - 1)
    while (number.GCD(k, p) != 1):
        k += 1
    return k

def blind(publicKey, m):
    k = getRandomCoPrime(publicKey.p - 1)
    r = pow(publicKey.g, k, publicKey.p)
    h = getRandomCoPrime(publicKey.p - 1)
    blindM = (h * m) % (publicKey.p - 1)
    return k, r, h, blindM

def sign(privateKey, k, r, blindM):
    return ((blindM - privateKey.x * r) * number.inverse(k, privateKey.p - 1)) % (privateKey.p - 1)

def unblind(publicKey, blindSignature, k, blindM, h):
    return ((number.inverse(h, publicKey.p - 1) - 1) * blindM * number.inverse(k, publicKey.p - 1) + blindSignature) % (publicKey.p - 1)

def verify(publicKey, signature, r, m):
    return (pow(publicKey.g, m, publicKey.p) == (pow(publicKey.y, r, publicKey.p) * pow(r, signature, publicKey.p)) % publicKey.p)

def generateKeyPair(keySize):
    privateKey = ElGamal.generate(keySize, Random.new().read)
    privateKey.x = int(privateKey.x)
    privateKey.y = int(privateKey.y)
    privateKey.p = int(privateKey.p)
    privateKey.g = int(privateKey.g)
    publicKey = privateKey.publickey()
    publicKey.p = int(publicKey.p)
    publicKey.g = int(publicKey.g)
    return privateKey, publicKey
