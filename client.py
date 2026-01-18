# Client to implement a simplified RSA algorithm to communicate securely with a server.
# The client initiates communication, exchanges cryptographic capabilities, and performs key exchange.
# It uses RSA for asymmetric encryption and AES for symmetric encryption of messages.
# The goal is to securely exchange a session key, verify a nonce, and perform secure computation of integer sums.

import socket
import math
import random
import sys
import simplified_AES
from NumTheory import NumTheory

# Author: Chevaughn Williams
# Last Modified: 2024-11-11
# Version: 0.1

class RSAClient:
    def __init__(self, address, port):
        """
        Initialize the client with server address and port.
        Attributes include:
        - `address`: Server IP address.
        - `port`: Server port number.
        - `socket`: Socket for communication.
        - `lastRcvdMsg`: Stores the last received message.
        - `sessionKey`: Symmetric key for AES encryption.
        - `modulus` (n): Server's RSA modulus.
        - `serverExponent` (e): Server's RSA public key exponent.
        """
        self.address = address
        self.port = int(port)
        self.socket = socket.socket()
        self.lastRcvdMsg = None
        self.sessionKey = None
        self.modulus = None
        self.serverExponent = None

    def connect(self):
        """Establish a connection to the server."""
        self.socket.connect((self.address, self.port))
        print("\nReady To Transmit Data\n")

    def send(self, message):
        """Send a message to the server."""
        self.socket.send(bytes(message, 'utf-8'))

    def read(self):
        """Read data from the server and store it in `lastRcvdMsg`."""
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Server is unavailable")

    def close(self):
        """Close the connection to the server."""
        print("\nClosing connection to", self.address)
        try:
            print("\nConnection Terminated\n")
            self.socket.close()
        except OSError as e:
            print(
                "Error: socket.close() exception for",
                f"{self.address}: {repr(e)}",
            )
        finally:
            self.socket = None

    def RSAencrypt(self, msg):
        """
        Encrypt a message using RSA.
        The encryption formula is: `ciphertext = (msg^e) mod n`.
        """
        if msg < self.modulus:
            return NumTheory.expMod(msg, self.serverExponent, self.modulus)

    def computeSessionKey(self):
        """Generate a random 16-bit session key for AES encryption."""
        self.sessionKey = random.randint(2 ** 15, 65536 - 1)

    def AESencrypt(self, plaintext):
        """Encrypt plaintext using AES with the session key."""
        simplified_AES.keyExp(self.sessionKey)  # Generate AES round keys.
        return simplified_AES.encrypt(plaintext)

    def AESdecrypt(self, cText):
        """Decrypt ciphertext using AES with the session key."""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def serverHello(self):
        """Generate the initial hello message to the server."""
        return "101 Hello 3DES, AES, RSA16, DH16"

    def sessionKeyMsg(self, nonce):
        """
        Create a message containing:
        - Encrypted session key using RSA.
        - Encrypted nonce using AES.
        """
        encryptedSessionKey = self.RSAencrypt(self.sessionKey)
        encryptedNonce = self.AESencrypt(nonce)
        return f"103 SessionKey {encryptedSessionKey}, {encryptedNonce}"

    def integersEncryptedMessage(self, firstInt, secondInt):
        """
        Create a message containing two integers encrypted using AES.
        """
        firstIntEncrypted = self.AESencrypt(firstInt)
        secondIntEncrypted = self.AESencrypt(secondInt)
        return f"113 IntegersEncrypted {firstIntEncrypted}, {secondIntEncrypted}"

    def splitString(self, msg, splitchar):
        """Split a string by a specified delimiter."""
        return msg.split(splitchar)

    def start(self):
        """
        Main logic for client-server communication:
        1. Send "Hello" message.
        2. Receive and parse server's public key and nonce.
        3. Generate a session key and send it encrypted.
        4. Verify nonce.
        5. Securely compute integer sums.
        """
        # Protocol constants
        commaDelimiter = ", "
        okMessage = "200 OK"
        errorMessage = "400 Error"
        serverHelloMessageStart = "102 Hello AES, RSA16, "
        serverNonceVerifiedMessage = "104 Nonce Verified"
        serverCompositeEncryptedMessageStart = "114 CompositeEncrypted "

        # Step 1: Connect and send hello
        self.connect()
        self.send(self.serverHello())
        print("\nHello Message Sent to Server")

        # Step 2: Receive server's hello
        self.read()
        print("\nHello Message Received from Server")
        print("Message: ", self.lastRcvdMsg)

        # Extract server's public key and nonce
        serverHelloResponse = self.lastRcvdMsg[len(serverHelloMessageStart):]
        serverKeys = self.splitString(serverHelloResponse, commaDelimiter)
        self.modulus = int(serverKeys[0])
        self.nonce = int(serverKeys[-1])
        self.serverExponent = int(serverKeys[1])

        print("\nKeys Extracted from Server Hello Message")
        print("Nonce: ", self.nonce)
        print("Modulus (n): ", self.modulus)
        print("Server Exponent (e): ", self.serverExponent)

        # Step 3: Generate and send session key message
        self.computeSessionKey()
        sessionKeyMessage = self.sessionKeyMsg(self.nonce)
        self.send(sessionKeyMessage)

        # Step 4: Verify nonce
        self.read()
        print("\nNonce Verification Message Received from Server")
        print("Message: ", self.lastRcvdMsg)

        if self.lastRcvdMsg == errorMessage:
            self.close()
            return

        # Step 5: Handle integer encryption and sum verification
        if self.lastRcvdMsg == serverNonceVerifiedMessage:
            firstInteger = int(input('First Integer: '))
            secondInteger = int(input('Second Integer: '))
            sumOfIntegers = sum([firstInteger, secondInteger])

            integersEncryptedMessage = self.integersEncryptedMessage(firstInteger, secondInteger)
            self.send(integersEncryptedMessage)

            # Receive composite sum from server
            self.read()
            print("\nCompositeEncrypted Message Received from Server")
            print("Message: ", self.lastRcvdMsg)

            serverCompositeEncryptedSum = self.lastRcvdMsg[len(serverCompositeEncryptedMessageStart):]
            decryptedServerCompositeSum = self.AESdecrypt(int(serverCompositeEncryptedSum))

            print("\nComposite Integer Sum Extracted from Server Message")
            print("Local Sum: ", sumOfIntegers)
            print("Server Sum: ", decryptedServerCompositeSum)

            # Verify results and respond to the server
            if sumOfIntegers == decryptedServerCompositeSum:
                self.send(okMessage)
                print("\nResponse Message Sent to Server:", okMessage)
            else:
                self.send(errorMessage)
                print("\nResponse Message Sent to Server:", errorMessage)

            self.close()

def main():
    """Driver function to initialize the client and start communication."""
    args = sys.argv
    if len(args) != 3:
        print("Please supply a server address and port.")
        sys.exit()
    print("Client of Chevaughn Williams")
    serverHost = str(args[1])
    serverPort = int(args[2])

    client = RSAClient(serverHost, serverPort)
    try:
        client.start()
    except (KeyboardInterrupt, SystemExit):
        exit()

if __name__ == "__main__":
    main()
