# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author:
# Last modified: 2024-11-11
# Version: 0.1.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES
from NumTheory import NumTheory

class RSAServer:
    """
    A server implementation that uses the RSA algorithm to exchange encrypted data
    with a client and validate the session through nonce verification.
    """

    def __init__(self, port, p, q):
        """
        Initializes the server, binds to the specified port, and generates RSA keys.

        Args:
            port (int): The port to bind the server.
            p (int): First prime number for key generation.
            q (int): Second prime number for key generation.
        """
        self.socket = socket.socket()
        # Allow reuse of the socket.
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)

        self.lastRcvdMsg = None
        self.sessionKey = None  # To store the symmetric session key.
        self.modulus = None  # RSA modulus (n).
        self.pubExponent = None  # Public RSA exponent (e).
        self.privExponent = None  # Private RSA exponent (d).
        self.nonce = None  # Random nonce for session validation.

        self.genKeys(p, q)  # Generate public-private RSA keys.
        self.start()

    def send(self, conn, message):
        """
        Sends a message to the client.

        Args:
            conn: The connection socket.
            message (str): The message to send.
        """
        conn.send(bytes(message, 'utf-8'))

    def read(self):
        """
        Reads a message from the client and stores it in `self.lastRcvdMsg`.
        """
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")

    def close(self, conn):
        """
        Closes the connection with the client.

        Args:
            conn: The connection socket.
        """
        print("Closing server side of the connection.")
        try:
            conn.close()
            print("\nConnection Terminated\n")
        except OSError as e:
            print(
                "Error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            conn = None  # Release the socket reference.

    def RSAencrypt(self, msg):
        """
        RSA encrypts a message using the public key.

        Args:
            msg (int): The message to encrypt.
        Returns:
            int: The RSA-encrypted message.
        """
        if msg < self.modulus:
            return NumTheory.expMod(msg, self.pubExponent, self.modulus)

    def RSAdecrypt(self, cText):
        """
        RSA decrypts ciphertext using the private key.

        Args:
            cText (int): The ciphertext to decrypt.
        Returns:
            int: The decrypted plaintext.
        """
        return NumTheory.expMod(cText, self.privExponent, self.modulus)

    def AESdecrypt(self, cText):
        """
        Decrypts ciphertext using the AES algorithm.

        Args:
            cText: The ciphertext to decrypt.
        Returns:
            int: The decrypted plaintext.
        """
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """
        Encrypts plaintext using the AES algorithm.

        Args:
            plaintext: The plaintext to encrypt.
        Returns:
            int: The ciphertext.
        """
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.encrypt(plaintext)

    def generateNonce(self):
        """
        Generates a unique nonce using a hash of the current time.
        """
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode('utf-8'))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

    def findE(self, phi):
        """
        Finds an appropriate public exponent `e` that is coprime with `phi`.

        Args:
            phi (int): The totient of the modulus.
        Returns:
            int: The public exponent.
        """
        for e in range(2, self.modulus):
            if NumTheory.gcd_iter(e, phi) == 1:
                return e
        return 1

    def genKeys(self, p, q):
        """
        Generates RSA public and private keys.

        Args:
            p (int): The first prime number.
            q (int): The second prime number.
        """
        phi_n = (p - 1) * (q - 1)
        self.modulus = p * q
        self.pubExponent = self.findE(phi_n)
        self.privExponent = NumTheory.ext_Euclid(phi_n, self.pubExponent)

        print("\nServer Keys Generated")
        print("Phi(n): ", phi_n)
        print("Modulus(n): ", self.modulus)
        print("Public Exponent(e): ", self.pubExponent)
        print("Private Exponent(d): ", self.privExponent)

    def clientHelloResp(self):
        """
        Generates a response string to the client's hello message.

        Returns:
            str: The response message containing server's public key and nonce.
        """
        self.generateNonce()
        return f"102 Hello AES, RSA16, {self.modulus}, {self.pubExponent}, {self.nonce}"

    def nonceVerification(self, decryptedNonce):
        """
        Verifies the received nonce.

        Args:
            decryptedNonce (int): The decrypted nonce from the client.
        Returns:
            bool: True if the nonce matches, False otherwise.
        """
        return self.nonce == decryptedNonce

    def compositeEncryptedMessage(self, firstInt, secondInt):
        """
        Constructs a composite message of encrypted integers.

        Args:
            firstInt (int): The first integer.
            secondInt (int): The second integer.
        Returns:
            str: The composite message.
        """
        sumOfIntegers = sum([firstInt, secondInt])
        encryptedIntegerSum = self.AESencrypt(sumOfIntegers)
        return f"114 CompositeEncrypted {encryptedIntegerSum}"

    def start(self):
        """
        The main server loop to process client requests.
        """
        commaDelimiter = ", "
        errorMessage = "400 Error"
        clientSessionKeyMessageStart = "103 SessionKey "
        serverNonceVerifiedMessage = "104 Nonce Verified"
        clientIntegersEncryptedMessageStart = "113 IntegersEncrypted "

        while True:
            connSocket, addr = self.socket.accept()

            clientHelloMessage = connSocket.recv(1024).decode('utf-8')
            print("\nHello Message Received from Client")
            print("Message: ", clientHelloMessage)

            self.send(connSocket, self.clientHelloResp())

            clientSessionKeyMessage = connSocket.recv(1024).decode('utf-8')
            print("\nSession Key Message Received from Client")
            print("Message: ", clientSessionKeyMessage)

            sesssionKeyMessage = clientSessionKeyMessage[len(clientSessionKeyMessageStart):]
            sessionKeyMessageEncryptedValues = sesssionKeyMessage.split(commaDelimiter)
            encryptedClientSessionKey = int(sessionKeyMessageEncryptedValues[0])
            encryptedClientNonce = int(sessionKeyMessageEncryptedValues[1])

            self.sessionKey = self.RSAdecrypt(encryptedClientSessionKey)
            decryptedNonce = self.AESdecrypt(encryptedClientNonce)

            if not self.nonceVerification(decryptedNonce):
                self.send(connSocket, errorMessage)
                self.close(connSocket)
                return
            else:
                self.send(connSocket, serverNonceVerifiedMessage)

                clientEncryptedIntegersMessage = connSocket.recv(1024).decode('utf-8')
                encryptedIntegersMessage = clientEncryptedIntegersMessage[len(clientIntegersEncryptedMessageStart):]
                encryptedIntegersMessageValues = encryptedIntegersMessage.split(commaDelimiter)
                firstEncryptedInteger = int(encryptedIntegersMessageValues[0])
                secondEncryptedInteger = int(encryptedIntegersMessageValues[1])

                firstDecryptedInteger = self.AESdecrypt(firstEncryptedInteger)
                secondDecryptedInteger = self.AESdecrypt(secondEncryptedInteger)

                compositeEncryptedMessage = self.compositeEncryptedMessage(
                    firstDecryptedInteger, secondDecryptedInteger
                )
                self.send(connSocket, compositeEncryptedMessage)

            self.close(connSocket)
            return


def is_prime(n):
    """
    Checks if a number is prime.

    Args:
        n (int): The number to check.
    Returns:
        bool: True if the number is prime, False otherwise.
    """
    for i in range(2, int(n / 2)):
        if n % i == 0:
            return False
    return True


def main():
    """
    Main driver function to initialize the server.
    """
    args = sys.argv
    if len(args) != 2:
        print("Please supply a server port.")
        sys.exit()

    PORT = int(args[1])
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()

    print("Server of Chevaughn Williams")

    stop = 0
    while stop == 0:
        print(
            """Enter prime numbers. One should be between 211 and 281,
            and the other between 229 and 307. The product of your numbers should
            be less than 65536"""
        )
        p = int(input("Enter P: "))
        q = int(input("Enter Q: "))

        isPPrime = is_prime(p)
        isQPrime = is_prime(q)

        if isPPrime and isQPrime:
            stop = 1
            print("P and Q are Prime Numbers")

            if (p * q < 65536):
                print("The product of P and Q is in range.")
            else:
                print("The product of P and Q is NOT in range.")
                stop = 0

        if not isPPrime:
            print("P is NOT a prime number.")
            stop = 0

        if not isQPrime:
            print("Q is NOT a prime number.")
            stop = 0

    server = RSAServer(PORT, p, q)
    server.start()


if __name__ == "__main__":
    main()
