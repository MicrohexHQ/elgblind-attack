#E. Mohammed et al. proposed a blind signature scheme, which did not meet the unforgeability.

from Crypto.Util import number
import elgblind

privateKey, publicKey = elgblind.generateKeyPair(256)

m = 0xdeadbeef
k, r, h, blindM = elgblind.blind(publicKey, m)
blindSignature = elgblind.sign(privateKey, k, r, blindM)

#Recovering the private key x
x = (number.inverse(r, publicKey.p - 1) * (blindM-k*blindSignature)) % (publicKey.p - 1)

#success rate ~50%
print(x == privateKey.x)
