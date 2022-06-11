# Secure Chat Application
This project implements a simple chat server using end-to-end Encryption, where clients can authenticate and establish a secure chat between each other.
The server uses an Ephemeral RSA key exchange implementation to authenticate and establish a secure channel with the user. After the authentication, client-server communication will use a symmetric encryption (AES-256-GCM) implementation, so users can issue requests to the server (get list of online user and request to chat).
As a request to chat is issued and accepted by both peers, the users will again run a the Ephemeral RSA symmetric key exchange, using the AES-256-GCM encryption on all their messages (E2EE).
