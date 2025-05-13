from tinyec import registry
from tinyec.ec import Curve, Point
import random
import ecfunc
import time

# Get Secp384r1 curve
curve1 = registry.get_curve("secp384r1")
p = curve1.field.p
a1 = curve1.a
b1 = curve1.b

# Create the twisted curve
d = -1
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

xP2 = 0xc842d2fdd7fae75e5e8dce3b8d3cee9820d92498599f98d8b0e437d4f3255a2807feaf44f17272d9026226aebc1e7f3f
yP2 = 0x5ddc86454aab639bf39efa0efd3fe6a4568bbe2708844b370e1083b8047868c6c9d75fefcae4a2eb8009319d37745a14
P2 = Point(curve2, xP2, yP2)

xQ2 = 0xb5e2867bdd90cd518bc39d62e58c7e6d2e6f287f843ee1da15c37c02a3be4dd74da92b8a173e56ba4836c2937cb68c56
yQ2 = 0x9d4c10281697f6ceb4d48166d6fe88ca04e2e57f39b7dec79314163e421e004c10ba1f21d9930c2060d0acbdf6ad6016
Q2 = Point(curve2, xQ2, yQ2)

# The backdoor key, i.e. the scalars such that bd1*Q1=P1 and bd2*Q2=P2
bd1 = 0x362e35363130204170706c6965642043727970746f67726170687920537072696e6720323032352053656d6573746572
bd2 = 0x5468616e6b20796f752c204d61737361636875736574747320496e73746974757465206f6620546563686e6f6c6f6779
key = (bd1, bd2)

param = (curve1, curve2, d, P1, P2, Q1, Q2)

print (hex(p-xP2))
print (hex(p-xQ2))

# Twisted Dual EC DRBG
def twisted_dual_ec_drbg (param, seed, length):

    curve1, curve2, d, P1, P2, Q1, Q2 = param
    p = curve1.field.p

    output = ""
    iters = int (length / 384) + 1
    s = seed
    for _ in range (iters):

        a, b = format(s, '0384b') [382:384]

        # compute the bits r of the random output
        if b == '0':
            r = (s*Q1).x
        else:
            r = ((s*Q2).x * pow (d, -1, p)) % p
        output += format(r, '0384b')

        # update the state s
        if a == '0':
            s = (s*P1).x
        else:
            s = ((s*P2).x * pow (d, -1, p)) % p

    return output [:length]

# Need to implement correctly
def backdoor_predictor (param, key, bits, length):
    chunks = len(bits) // 384
    bd1, bd2 = key
    curve1, curve2, d, _, _, _, _ = param
    p = curve1.field.p
    for i in range (chunks - 2):
        # Chunk of 384 bits of the DBRG output
        r = int (bits [384*i:384*(i+1)], 2)
        point1 = ecfunc.find_point_from_x(curve1, r)
        point2 = ecfunc.find_point_from_x(curve2, (r * d) % p)
        if point1 != None:
            s = (bd1 * point1).x
        elif point2 != None:
            s = ((bd2 * point2).x * pow (d, -1, p)) % p
        else:
            return None # This should not happen if curve2 is a twist of curve1
            
        # We have a guess s of the secret state

        a, b = format(s, '0384b') [382:384]

        # Compute the corresponding guess for the next 384 bits of the output, and check against the actual output
        if a == '0':
            s = (s*P1).x
        else:
            s = ((s*P2).x * pow (d, -1, p)) % p

        if b == '0':
            r = (s*Q1).x
        else:
            r = ((s*Q2).x * pow (d, -1, p)) % p
        
        if format(r, '0384b') == bits[384*(i+2):384*(i+3)]:
            # If they match, the state guess was correct, and we can determine the rest of the DRBG output by running the DRBG on the uncovered state.
            return bits[:384*(i+2)] + twisted_dual_ec_drbg (param, s, length-384*(i+2))
    else:
        return None

# Example: Generate 10000 bits using the DRBG, feed the first 3840 to an adversary with the backdoor (repeat 20 times)

output_length = 10000
bits_given_to_predictor = 3840

for _ in range (20):

    seed = random.randint(1,2**384)
    print ("Seed: " + str(seed))
    start = time.time ()
    random_bits = twisted_dual_ec_drbg (param, seed, output_length)
    print ("DRBG:      " + random_bits)
    print ("Generated " + str(output_length) + " bits in " + str(time.time () - start) + " seconds.")

    start = time.time ()
    prediction = backdoor_predictor (param, key, random_bits[:bits_given_to_predictor], output_length)
    # should be the same as random_bits with high probability, else None
    if prediction != None:
        print ("Predictor: " + prediction)
        if random_bits == prediction:
            print ("Predictor used first " + str(bits_given_to_predictor) + " bits of the output and the backdoor key to correctly predict all " + str(output_length) + " bits of the output in " + str(time.time ()-start) + " seconds.")
        else:
            print ("Predictor was wrong!") # should not happen
    else:
        print ("Got unlucky; predictor could not recover state.") # should happen with small probability
