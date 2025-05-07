from tinyec import registry
from tinyec.ec import Curve, Point
import random
import ecfunc

# Get Secp384r1 curve
curve1 = registry.get_curve("secp384r1")
p = curve1.field.p
a1 = curve1.a
b1 = curve1.b

# Create the twisted curve
d = 19
a2 = (d**2 * a1) % p
b2 = (d**3 * b1) % p
curve2 = Curve(field=curve1.field, a=a2, b=b2, name="secp384r1_twist")

# Due to the way the twist is constructed, coordinates of its points must be multiplied by d inverse when implementing the DRBG

# Define points P1, Q1, P2, Q2 by their coordinates (in hexadecimal)

xP1 = 0x43a8df013becd277e4025216bc90897fde4ca279023e0a4e44e56e8901a6c99760b571f069a57870fbe2056786383c5f
yP1 = 0xb3b25f84b93f6e08fff60c6c2a54a265d6011fc2dc1e4b77f3225615f083371e8336b0cf482a8359ccf23701bd2ee36c
P1 = Point(curve1, xP1, yP1)

xQ1 = 0x1c36145bead2c4d731d8c42e5f2f99ff6863828635fa58039baeaad0b7cb1f2f1a327c68e4a9e365a02787f213f69873
yQ1 = 0xb823b33bfcf9984ec3238e0651299a0c40739bdf10fee3ed97573747a85fa0d1d46d9a40a23bf25bed06afc63f2daaa9
Q1 = Point(curve1, xQ1, yQ1)

xP2 = 0x68ec369f1ad44d8ba20da403bdd3a0c105a1bec2b6001b46048e706dd570cc63f32ce014063397d2fec913220cb11566
yP2 = 0x925d51c198eab4c66961b624dfc9405d7387accd2c61348083c272f2d1848f4ec8d34ce3bc334db8d358bdedd1f11309
P2 = Point(curve2, xP2, yP2)

xQ2 = 0xb807e0cde2b2f9ff26446a6b30b7a945c25ccacdeedc649f284d2fc745dbe3d67bfe179917df1f130272f11244ae6579
yQ2 = 0x0d0df59a0de26c6a510963ed172eea8f70510913d336b992276519beb64bae4157f0c7e34158282c508d738afe4ba1f7
Q2 = Point(curve2, xQ2, yQ2)

param = (curve1, curve2, d, P1, P2, Q1, Q2)

# The backdoor key, i.e. the scalars such that bd1*Q1=P1 and bd2*Q2=P2
bd1 = 0x362E35363130204170706C6965642043727970746F67726170687920537072696E6720323032352053656D6573746572
bd2 = 0x5468616E6B20796F752C204D61737361636875736574747320496E73746974757465206F6620546563686E6F6C6F6779
key = (bd1, bd2)

# Twisted Dual EC DRBG
def twisted_dual_ec_drbg (param, seed, length):

    curve1, curve2, d, P1, P2, Q1, Q2 = param
    p = curve1.field.p

    output = ""
    iters = int (length / 384) + 1
    s = seed
    for _ in range (iters):

        a, b = format(s, '0384b') [382:384]

        # update the state s
        if a == '0':
            s = (s*P1).x
        else:
            s = ((s*P2).x * pow (d, -1, p)) % p

        # compute the bits r of the random output
        if b == '0':
            r = (s*Q1).x
        else:
            r = ((s*Q2).x * pow (d, -1, p)) % p
        output += format(r, '0384b')

    return output [:length]

# Need to implement correctly
def backdoor_predictor (param, key, bits, length):
    if len (bits) >= 256:
        bd1, bd2 = key
        curve1, curve2, d, _, _, _, _ = param
        p = curve1.field.p
        # First 256 bits of the DBRG output
        r1 = int (bits [:256], 2)
        point1 = ecfunc.find_point_from_x(curve1, r1)
        point2 = ecfunc.find_point_from_x(curve2, (r1 * d) % p)
        print (point1 == None, point2 == None)
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
seed = random.randint(1,2**384)
print ("Seed: " + str(seed))
random_bits = twisted_dual_ec_drbg (param, seed, 10000)
print ("DRBG:      " + random_bits)

"""
prediction = backdoor_predictor (param, key, random_bits[:3840], 10000) # should be the same as random_bits with high probability, else None
print ("Predictor: " + prediction)
print (random_bits == prediction)
"""
