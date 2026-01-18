# Secure Client-Server Communication (RSA + AES)

A Python-based client-server application that demonstrates secure communication using a simplified RSA key exchange combined with AES symmetric encryption over sockets.

This project is for educational purposes only and does not represent production-grade cryptography.

## Overview

The system simulates a secure communication protocol between a client and a server:
- RSA is used to securely exchange a session key
- AES is used for encrypting subsequent messages
- A nonce is used to prevent replay attacks
- Encrypted integers are exchanged and verified for integrity

## Features
- Client-server communication using TCP sockets
- RSA public/private key generation
- Secure session key exchange
- AES encryption and decryption
- Nonce verification for session integrity
- Encrypted computation and validation

## Protocol Flow
1. Client sends a Hello message with supported algorithms
2. Server responds with RSA public key and nonce
3. Client generates a session key and encrypts it using RSA
4. Client encrypts the nonce using AES
5. Server verifies the nonce
6. Client sends encrypted integers
7. Server computes and returns encrypted sum
8. Client verifies the result

## Usage

### Start the server

python3 server.py <port>
