from Crypto.Cipher import AES
from Crypto.Hash import SHA

def get_cryptor( key, alg, iv ):
    if alg == "AES.MODE_ECB" and key is not None:
        if iv == None:
            return AES.new(key, AES.MODE_ECB)
    elif alg == "SHA":
        return SHA.new()
    else:
        return None

# h = SHA.new()           // SHA1Hash object
# h.update(b'Hello')
# print h.hexdigest()
#
# key = 'mysecretpassword'
# plaintext = 'Secret Message A'

# // AES Cipher Object
# encobj = AES.new(key, AES.MODE_ECB)

# // Calling encrypt function using Cipher Object
# ciphertext = encobj.encrypt(plaintext)

# Resulting ciphertext in hex
# print ciphertext.encode('hex')
#
# p = encobj.decrypt(ciphertext)
#
# print p.encode()



# if __name__ == '__main__':
#     mode == 'ENC'
#     data = "hello world"
#     if mode == 'ENC':
#         print encrypt( key, data )
#     elif mode == 'DEC':
#         print decrypt( key, data )
#     else:
#         sys.exit(1)
