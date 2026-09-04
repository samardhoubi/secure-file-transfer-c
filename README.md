**Secure File Transfer in C

A university project implementing a secure client-server application for encrypted file transfer.

Features
Client-server communication using TCP sockets
File encryption using POET
Session key exchange using Libsodium
Server authentication using digital signatures
Verification of the server signature before file transfer
Technologies
C
TCP/IP sockets
Libsodium
POET authenticated encryption
Project Structure
.
├── aes.c
├── aes.h
├── client.c
├── server.c
├── poet.c
├── poet.h
├── helper.h
├── gen_signkey.c
└── Makefile
Requirements

The project requires:

GCC
Make
Libsodium
Build

Compile the project using:

make
Key Generation

Generate the server signing key pair:

./gen_signkey

This creates:

server.pk — public signing key
server.sk — private signing key

Important: Never upload server.sk to a public repository.

Usage

Start the server:

./server

Then, in another terminal, send a file:

./client filename
Security

The client and server establish a session key using Libsodium. The server signs its public key, and the client verifies the signature before continuing the communication.

Academic Project

This project was developed as part of a university course on cryptography and IT security.
**
