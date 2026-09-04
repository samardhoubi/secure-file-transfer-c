# Secure File Transfer in C

A university project implementing a secure client-server application for encrypted file transfer.

## Features

- Client-server communication using TCP sockets
- File encryption using POET
- Session key exchange using Libsodium
- Server authentication using digital signatures
- Verification of the server signature before file transfer

## Technologies

- C
- TCP/IP sockets
- Libsodium
- POET authenticated encryption

## Project Structure

```text
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
