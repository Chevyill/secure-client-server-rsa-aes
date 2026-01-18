# Code to carry out Number Theory functions

# Author: fokumdt
# Last modified: 2024-11-08
# Version: 0.0.2
#!/usr/bin/python3

import math

class NumTheory:
    @staticmethod
    def expMod(b,n,m):
        """Computes the modular exponent of a number"""
        """returns (b^n mod m)"""
        if n == 0:
            return 1
        elif n%2 == 0:
            return NumTheory.expMod((b*b)%m, n/2, m)
        else:
            return(b*NumTheory.expMod(b,n-1,m))%m
    
    @staticmethod
    def gcd_iter(u, v):
        """Iterative Euclidean algorithm to find the greatest common divisor of
           integers u and v"""
        while v:
            u, v = v, u % v
        return abs(u)
    
    @staticmethod
    def lcm(u, v):
        """Returns the lowest common multiple of two integers, u and v"""
        return int((u*v)/NumTheory.gcd_iter(u, v))
    
    @staticmethod
    def ext_Euclid(m,n):
        """Extended Euclidean algorithm. It returns the multiplicative
            inverse of n mod m"""
        a = (1,0,m)
        b = (0,1,n)
        while True:
            if b[2] == 0: return a[2]
            if b[2] == 1: return int(b[1] + (m if b[1] < 0 else 0))
            q = math.floor(a[2]/float(b[2]))
            t = (a[0] - (q * b[0]), a[1] - (q*b[1]), a[2] - (q*b[2]))
            a = b
            b = t
    
    @staticmethod
    def IsValidGenerator(g, p):
        """Validation of generator and prime"""
        x = set()
        for i in range(1,p): #to iterate on the powers of the generator modulo p
            x.add(NumTheory.expMod(g,i,p))
        if (len(x) == (p-1)) and (g < p):
            return True
        else:
            return False
    
    @staticmethod
    def IsPrime(n):
        """Returns true if the number, n, is prime"""
        if n == 2 or n == 3:
            return True
        elif n <= 1 or n%2 == 0 or n%3 == 1:
            return False
        for i in range(5, int(math.sqrt(n))+1, 6):
        # Check all numbers of the form 6k+1, with a step size of 6
            if n % i == 0 or n % (i+2) == 0:
                return False
        return True
