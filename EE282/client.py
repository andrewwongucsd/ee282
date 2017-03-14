import socket
import sys
import json
from operator import xor
from random import randint
import bbs
import utility
import cryptor
import base64
import datetime


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect the socket to the port where the server is listening
server_address = ('localhost', 8000)
# print >>sys.stderr, ' connecting to %s port %s' % server_address
sock.connect(server_address)
_p = 197221152031991558322935568090317202983
_g = 2

try:
    # Timing for Authentication
    t1 = datetime.datetime.now()
    # Attempt Counter
    attempt = 0
    # Username from Client
    in_username = None
    # Password from Client
    in_password = None
    # Xa from Client
    in_Xa = None
    print "Preparing to send DH Message1"
    step = 1
    while True:
        if step == 1:
            # Attempt Increment
            attempt = attempt + 1
            # Over-attempt results in Goodbye
            if attempt == 4:
                sock.close()
                break
            in_username = raw_input("Enter Username(e.g:Alice): (Attempt-"+str(attempt)+"):")
            in_password = raw_input("Enter Password(e.g:Alice): (Attempt-"+str(attempt)+"):")
            in_Xa = raw_input("Enter secret of Alice(Xa): ")

            # message transfer to sever by 'message' and deliminter '||'
            message = in_username + "||"
            message = message + "Secure DH||"
            message = message + str(_p) +"||"
            message = message + str(_g) +"||"
            g_Xa_mod_p = pow(_g, int(in_Xa), _p)
            paddedPassword = utility.padding(in_password, str(g_Xa_mod_p))
            ciphertext = utility.sxor(paddedPassword, str(g_Xa_mod_p))

            # Be prepared to send message to the server in the following Format
            # Format for message 1
            # {username , request, p, g, Encrypted(Password, g_Xa mod p) via xor}
            message = message + ciphertext
            utility.printer("Message 1:Sent from Alice to Server")
            print "ClientID:", in_username
            print "Request:", "Secure DH"
            print "P=", _p
            print "g=", _g
            print "g_Xa", str(g_Xa_mod_p).encode('hex')
            print "g_Xa^Pass(Hex)", ciphertext.encode('hex')
            sock.sendall(message)
            step = 2
        elif step == 2:
            data = sock.recv(4096)
            # if 'Attempt-X' means failure from Server
            if data[0:len("Attempt-")] == "Attempt-":
                step = 1
                try:
                    if int(data[len("Attempt-")]) == 3:
                        print "3 attempts has reached. bye."
                        sock.close()
                    else:
                        print "back to step ", str(step)
                except ValueError:
                    print "something goes wrong. bye."
                    sock.close()
                    break
            else:
                print >>sys.stderr, 'received "%s"' % data
                step = 3
        elif step == 3:
            utility.printer("Message 2: Received from Server")
            array = data.split("||")
            print "g_Xb^Pass(In Hex):", array[0].encode('hex')
            gXs = utility.sxor(array[0],utility.padding(in_password, array[0] ))
            print "Decrypted g_Xb", gXs
            Kas = pow(int(gXs), int(in_Xa), _p)
            print "*"*20,"Alice computes Symmetric Key K_AS","*"*20
            print "Computed Symmetric Key K_AS(In Hex):", hex(Kas)
            encryptedPaddedNs = array[1]
            c = cryptor.get_cryptor(utility.long_to_bytes(Kas), "AES.MODE_ECB", None)
            plaintext = c.decrypt(encryptedPaddedNs)
            Ns = plaintext.rstrip('{')
            print "Decrypted Ns:", Ns
            utility.printer("Message 3: Sent from Alice to Server")
            Na_index = raw_input("Enter the seed for calculating Nonce:")
            Na, Nab = bbs.bbsone(int(Na_index))
            print "Na: ", Nab
            NsXorNa = utility.sxor(Ns ,utility.padding(str(Na), Ns))
            print "(Ns || Na): ", NsXorNa

            ciphertext_1 = in_username
            paddedNsXorNa, _ = utility.pad(NsXorNa)
            ciphertext_2 = c.encrypt(paddedNsXorNa)

            # Format of Message 3
            # {ID, Encrypted(XOR(Na, Ns) with AES)}
            message = ciphertext_1+"||"+ciphertext_2
            print >>sys.stderr, ' sending "%s"' % message
            sock.sendall(message)
            step = 4
        elif step == 4:
            data = sock.recv(4096)
            if data[0:len("Attempt-")] == "Attempt-":
                try:
                    if int(data[len("Attempt-")]) == 3:
                        print "3 attempts has reached. bye."
                        sock.close()
                    else:
                        step = 1
                except ValueError:
                    print "something goes wrong. bye."
                    sock.close()
            print >>sys.stderr, 'received "%s"' % data
            step = 5
        elif step == 5:
            c = cryptor.get_cryptor(utility.long_to_bytes(Kas), "AES.MODE_ECB", None)
            paddedData = c.decrypt(data)
            receivedNa = paddedData.rstrip('{')
            utility.printer("Message4: Received from Server")
            if receivedNa != str(Na):
                print "bad Na received."
                step = 1
            print "Decrypted Na:", str(Na)
            step = 6
        elif step == 6:
            print "*"*20, "Successful DH Key Exchange and Authentication", "*"*20
            print ""
            print "*"*20, "Proceeding to encrypted file transfer", "*"*20
            print "Alice has been successfully authenticated!"
            message = raw_input("For Downloading 'helpme.text' please enter y? :")
            message = message.strip().upper()
            sock.sendall(message)
            hashfile = None
            with open("helpme.text", 'wb') as f:
                # print 'File Opened ',"helpme.text"
                receivedData = ""
                print "Received Filename: helpme.text"
                print "Transferring file...."
                t2 = datetime.datetime.now()
                while True:
                    try:
                        data = sock.recv(4096)
                        # Special way to retrieve hash of the file.
                        # because of multiple back-and-forth.
                        rippedData = data.split("||")
                    except socket.timeout, e:
                        err = e.args[0]
                        # this next if/else is a bit redundant, but illustrates how the
                        # timeout exception is setup
                        if err == 'timed out':
                            sleep(1)
                            print 'recv timed out, retry later'
                            continue
                        else:
                            print e
                            break
                    except socket.error, e:
                            # Something else happened, handle error, exit, etc.
                        print e
                        break
                    else:
                        if len(data) == 0:
                            # print 'orderly shutdown on server end'
                            break
                        else:
                            if len(rippedData) == 2:
                                if len(rippedData[1]) > 0:
                                    # print "hash:", rippedData[1]
                                    hashfile = rippedData[1]
                            receivedData = receivedData + rippedData[0]
                c = cryptor.get_cryptor(utility.long_to_bytes(Kas), "AES.MODE_ECB", None)
                h = cryptor.get_cryptor(None, "SHA", None)
                h.update(receivedData)
                paddedData = c.decrypt(receivedData)
                t3 = datetime.datetime.now()
                # print paddedData

                # print "h.hexdigest(): ", h.hexdigest()
                data = paddedData.rstrip('{')
                # print data
                f.write(data)
                print "Received Hash is:", hashfile
                print "*"*50
                print ""
                print "Hash Computed is"
                print h.hexdigest()
                print "Received file from Server"
                print "**File Stored in Alice's coimputer"
                print "Closing the client"
                t4 = datetime.datetime.now()
                print "*"*50
                print "Estimated time taken for DH Key Exchange:", t4-t1
                print "Estimated time taken for file encryption and transfer:", t3-t2
                print "*"*50
                attempt = 4
                sock.close()
                break

finally:
    print >>sys.stderr, ' Socket Closing. '
    sock.close()
