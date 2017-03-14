import socket
import sys
from time import sleep
import json
import utility
import bbs
import cryptor
import socket
import base64
from Crypto.Hash import SHA
import os

# Create a TCP/IP socket (socket.SOCK_DREAM = UDP)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('localhost', 8000)
sock.bind(server_address)
print "Server socket created"
print "Socket is passively listening in port number 8000 for incoming client connections"

sock.listen(5)
combo = {}
combo["admin"] = "password"
combo["admin1"] = "password"
combo["admin2"] = "password"
combo["admin3"] = "password"
combo["admin4"] = "password"
combo["admin5"] = "password"
combo["admin6"] = "password"
combo["admin7"] = "password"
combo["admin8"] = "password"
combo["admin9"] = "password"
combo["admin10"] = "password"


while True:
    print "Passively listening for incoming client connections..."
    conn, client_address = sock.accept()
    try:
        _p = None
        _g = None
        _username = None
        _password = None
        _Kas = None
        _Xb = None
        _attempt = 0
        _step = 1
        while True:
            print "step", str(_step), " Attempt-", str(_attempt)
            if _step == 1:
                _attempt = _attempt + 1
                # avoid over attempt
                if _attempt == 4:
                    print "3 attempts has reaches. The connection closes."
                    conn.close()
                    break
                _p = None
                _g = None
                _username = None
                _password = None
                _Kas = None
                _Xb = None
                data = conn.recv(4096)
                _step = 2
            elif _step == 2:
                utility.printer("Message 1:Received from Alice")
                array = data.split("||")
                _p = int(array[2])
                _g = int(array[3])
                _username = array[0]
                try:
                    _password = combo[_username]
                except KeyError:
                    print "Unable to Authneticate the client"
                    _step = 1
                    s = "Attempt-"+str(_attempt)
                    conn.sendall(s)
                    continue
                ciphertext = array[4]
                print "Client ID:", array[0]
                print "Value of p chosen :", int(array[2])
                print "Value of g chosen :", int(array[3])
                print "g_Xa^pass:", array[4].encode('hex')

                _Xb = raw_input("Enter Server secret (Xb):")
                _Xb = int(_Xb)
                g_Xb_mod_p = pow(_g, _Xb, _p)
                print "g_Xb = g^Xb mod p =", str(g_Xb_mod_p)

                # padding password for exclusive or
                paddedPassword = utility.padding(_password, ciphertext)
                g_Xa = utility.sxor(paddedPassword, ciphertext)
                try:
                    _Kas = pow(int(g_Xa), _Xb, _p)
                except ValueError:
                    print "Unable to Authneticate the client"
                    _step = 1
                    s = "Attempt-"+str(_attempt)
                    conn.sendall(s)
                    continue
                print "Decrypted g_Xa: ", g_Xa
                print "*"*20, "Server comutes Symmetric K_AS", "*"*20

                print "Computed Symmetric Key K_AS(In Hex):", hex(_Kas)
                print ""
                print ""
                print ""
                utility.printer("Message2: Sent from Server to Alice")
                ns_index = raw_input("Enter the Seed for calculating Nonce:")
                Ns, Nsb = bbs.bbsone(int(ns_index))
                print "Blum Blum Shub generated Ns: ", Nsb

                paddedPassword = utility.padding(_password, str(g_Xb_mod_p))
                ciphertext_1 = utility.sxor(paddedPassword, str(g_Xb_mod_p))
                print "g_Xb^Pass:", ciphertext_1.encode('hex')

                # padding to fit the size of AES
                paddedns, _ = utility.pad(str(Ns))
                c = cryptor.get_cryptor(utility.long_to_bytes(_Kas), "AES.MODE_ECB", None)
                ciphertext_2 = c.encrypt(paddedns)
                # Format of Message 2
                # {Encrypted(Password, g_Xs mod p), Encrypted(Kas, Ns)}
                s = ciphertext_1+"||"+ciphertext_2
                conn.sendall(s)
                _step = 3
            elif _step == 3:
                data = conn.recv(4096)
                print >>sys.stderr, 'received "%s"' % data
                _step = 4
            elif _step == 4:
                array = data.split("||")
                ciphertext = array[1]
                c = cryptor.get_cryptor(utility.long_to_bytes(_Kas), "AES.MODE_ECB", None)
                plaintext = c.decrypt(ciphertext)
                # possible correct Na
                Na = utility.sxor(str(_Xb), plaintext)
                # Remove Padder
                Na = Na.rstrip('{')
                utility.printer("Message3: Received from Alice")
                print "Username: ", array[0]
                print "Decrypted Nonce is"
                print plaintext
                print "Received Na:",Na

                if array[0].strip() != _username:
                    print "Username is wrong. Unable to Authneticate the client"
                    step = 1
                    s = "Attempt-"+str(_attempt)
                    conn.sendall(s)
                    continue

                # Padding to fit AES Encryption
                paddedNa, _ = utility.pad(Na)
                ciphertext_1 = c.encrypt(paddedNa)
                s = ciphertext_1
                # Format for Message 4
                # {Encrypted(Kas, Na)}
                conn.sendall(s)
                utility.printer("Message4:Sent from Server to Alice")
                print "E(K_AS,Na)"
                print ciphertext_1
                _step = 5
            elif _step == 5:
                data = conn.recv(4096)
                print >>sys.stderr, 'received "%s"' % data
                if data.strip().upper() == 'Y':
                    file_descriptor = open("data/helpme.text", "rb")
                    print "File Opened data/helpme.text"
                    b = os.path.getsize("data/helpme.text")
                    chunk = file_descriptor.read(b)
                    c = cryptor.get_cryptor(utility.long_to_bytes(_Kas), "AES.MODE_ECB", None)

                    paddedChunk, _ = utility.pad(chunk)

                    chunk = c.encrypt(paddedChunk)
                    # SHA-1 Encryption for file transfer
                    h = cryptor.get_cryptor(None, "SHA", None)
                    h.update(chunk)
                    chunk = chunk +"||"+h.hexdigest()
                    conn.sendall(chunk)
                    print "Request file has been transferred to Alice"
                    print "Terminating connection with Alice"
                    break
                else:
                    print "Terminating connection with Alice"
                    break
    finally:
        conn.close()
