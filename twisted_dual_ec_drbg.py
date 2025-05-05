from tinyec import registry
from tinyec.ec import Curve, Point
import random
import ecfunc

# Get Secp256r1 curve
curve1 = registry.get_curve("secp256r1")
p = curve1.field.p
a1 = curve1.a
b1 = curve1.b

# Create the twisted curve
d = 3
a2 = (d**2 * a1) % p
b2 = (d**3 * b1) % p
curve2 = Curve(field=curve1.field, a=a2, b=b2, name="secp256r1_twist")

# Due to the way the twist is constructed, coordinates of its points must be multiplied by d inverse

# Define points P1, Q1, P2, Q2 by their coordinates (in hexadecimal)

xP1 = 0x2def918fd68d15bc27742e5499cfe9df4e3405fb6f03dccef9e11cf8986ef60d
yP1 = 0x80cb4cbaee8a37f0d8336033ddb0f4d15f064d17deb110e7668948de470575c7
P1 = Point(curve1, xP1, yP1)

xQ1 = 0x5822f5aa237a91ac8b7be9a5614b3ae34bc0aa5022d234c38e3a287de60c0078
yQ1 = 0x6717d95400a7b6a78a0b6499816772b7d0965b0bd8f516979f790ea0868c5959
Q1 = Point(curve1, xQ1, yQ1)

xP2 = 0xf9fb6d843d24d0b61eaeef05d4e53b1bd0290afd95124745acdc2576f36bfe75
yP2 = 0xac8a43049931c62b31d2f6606f7e14ad6b0db530519433121f07d461bf22a84f
P2 = Point(curve2, xP2, yP2)

xQ2 = 0x2424f07d29fb8133d962bfd7a1e5b296b1cead6c5a482d6d29c99f9d85b2e5fc
yQ2 = 0x292e87681c1c09c4f4c7dc869e3e8d89353bef62f95078130704aff1b4b0f617
Q2 = Point(curve2, xQ2, yQ2)

param = (curve1, curve2, d, P1, P2, Q1, Q2)

# The backdoor key, i.e. the scalars such that bd1*Q1=P1 and bd2*Q2=P2
bd1 = 0xf7377a64f51def12dddfcbd40c65b5edcda9d18c058ec8d129b2a5868a40fc23
bd2 = 0xdb692bb9ab34f817552a6e811ae77eba2f62562a7d01a5effe0ba013aa5ceff6
key = (bd1, bd2)

# Twisted Dual EC DRBG
def twisted_dual_ec_drbg (param, seed, length):

    curve1, curve2, d, P1, P2, Q1, Q2 = param
    p = curve1.field.p

    output = ""
    iters = int (length / 256) + 1
    s = seed
    for _ in range (iters):

        # update the state s
        if format(s, '0256b') [255] == '0':
            s = (s*P1).x
        else:
            s = ((s*P2).x * pow (d, -1, p)) % p

        # compute the bits r of the random output
        if format(s, '0256b') [255] == '0':
            r = (s*Q1).x
        else:
            r = ((s*Q2).x * pow (d, -1, p)) % p
        output += format(r, '0256b')

    return output [:length]

# Given the backdoor and the first >= 256 bits of TDEC DBRG output, predicts the first [length] bits of the output
def backdoor_predictor (param, key, bits, length):
    if len (bits) >= 256:
        bd1, bd2 = key
        curve1, curve2, d, _, _, _, _ = param
        p = curve1.field.p
        # First 256 bits of the DBRG output
        r1 = int (bits [:256], 2)
        point1 = ecfunc.find_point_from_x(curve1, r1)
        point2 = ecfunc.find_point_from_x(curve2, (r1 * d) % p)
        if point1 != None:
            s2 = (bd1 * point1).x
        elif point2 != None:
            s2 = ((bd2 * point2).x * pow (d, -1, p)) % p
        else:
            # This should not happen if curve2 is a twist of curve1
            return None
            
        # The state s2 has been uncovered
        # Generating the next 256 bits
        if format(s2, '0256b') [255] == '0':
            r2 = (s2*Q1).x
        else:
            r2 = ((s2*Q2).x * pow (d, -1, p)) % p

        if length >= 512:
            return bits[:256] + format(r2, '0256b') + twisted_dual_ec_drbg (param, s2, length-512)
        else:
            return (bits[:256] + format(r2, '0256b'))[:length]
    else:
        return None

# Example

seed = random.randint(1,2**256)
print ("Seed: " + str(seed))
random_bits = twisted_dual_ec_drbg (param, seed, 2048)
prediction = backdoor_predictor (param, key, random_bits[:256], 2048)
print ("DRBG:      " + random_bits)
print ("Predictor: " + prediction)
print (random_bits == prediction)
