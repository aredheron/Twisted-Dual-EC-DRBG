from tinyec.ec import Curve, Point
from sympy.functions.combinatorial.numbers import legendre_symbol
import random
import math


# Find quadratic non-residue mod p
def find_quadratic_non_residue(p):
    for d in range(2, p):
        if legendre_symbol(d, p) == -1:
            return d
    return None

# Run Tonelli-Shanks algorithm to squareroot n mod p
def tonelli_shanks(n, p):
    assert legendre_symbol(n, p) == 1, "n is not a quadratic residue modulo p"
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, Q, p)
    x = pow(n, (Q + 1) // 2, p)
    t = pow(n, Q, p)
    m = S
    while t != 1:
        i, temp = 0, t
        while temp != 1 and i < m:
            temp = pow(temp, 2, p)
            i += 1
        if i == m:
            return None
        b = pow(c, 2 ** (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    return x

# Find point with given x coordinate (return None if it doesn't exist)
def find_point_from_x(curve, x):
    p = curve.field.p
    rhs = (x**3 + curve.a * x + curve.b) % p
    if rhs == 0: # very unlikely to happen
        return Point(curve, x, 0)
    if legendre_symbol(rhs, p) == 1:
        y = tonelli_shanks(rhs, p)
        return Point(curve, x, y)
    return None

# Find random point on curve
def find_random_point(curve):
    p = curve.field.p
    while True:
        x = random.randint(0, p-1)
        point = find_point_from_x(curve, x)
        if point != None:
            return point
