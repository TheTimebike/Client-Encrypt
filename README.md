# Client-Encrypt
ClientEncrypt is an open-sourced, object-oriented chat application with several layers of security. While I am fairly confident in its security, I am not a professional in the cybersecurity field and it should be taken with a grain of salt. The server-side application runs headless, but the client-side application has a GUI made in tkinter.

In order to maintain a log of events if anything goes wrong, the server-side application has a builtin logging function that can easily be disabled by changing a variable in the Logging class. To keep user privacy, this does not log who sent the messages, but does log the messages themselves. This can be easily disabled through light editing.

The server-side application will also log the IP address of connected users and various other information about what they did while connected to the server. The client-side application does not log any actions, bu does print errors and information to the console for easy debugging. This can be disabled in the same way that the server-side logging could be.

## Security

ClientEncrypt makes use of a round-robin RSA encrypted end-to-end messaging system, where the server manages each of the client's public keys individually, and switches between keys to send each user their own uniquely encrypted message. These RSA keys are generated upon the connection to the server, and will generate a new set of keys everytime you connect/disconnect. You can also request a new set of keys in the security tab if you are worried that something has gone wrong or someone has access to them.

To login to the chatroom, you would have to provide a password which is securely hashed and sent across the network, once again being encrypted with RSA encryption, to the server, where it compares it to a pre-hashed password to ensure that no one peeking at the source code can see the password. This password is not stored anywhere in plaintext, and at the start of the Server.py file, there is a function to generate a new hashed password if you wish to change it.

Additionally, there is built-in functionality for an md5 checksum on the application, to ensure that the client is who they say they are. This is currently disabled, however, due to unreliability and the unavalibility of a non-windows compiled application.

## Dependencies 

Python 3

bcrypt

rsa

hashlib

socket

threading

json

regex (re)


## Client

tkinter

## Server

time
