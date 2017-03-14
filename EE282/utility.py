from binascii import unhexlify
from Crypto.Cipher import AES
import sys
import math

PADDING = '{'

def strBin(st):
    return ''.join(format(ord(x), 'b') for x in st)
def sxor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))
def padding(s1, s2):
    return s1 + PADDING * (len(s2) - len(s1))
def pad(s):
    return s + PADDING * (AES.block_size - len(s) % AES.block_size), (AES.block_size - len(s) % AES.block_size)
def printer(s):
    l = 0
    if len(s) % 2 == 0:
        l = len(s)/2
    else:
        l = (len(s)/2) + 1
    print "*"*l*4
    print "*"*l, s, "*"*l
    print "*"*l*4
def long_to_bytes (val, endianness='big'):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = unhexlify(fmt % val)
    if endianness == 'little':
        s = s[::-1]
    return s
if __name__ == '__main__':
    long_to_bytes()
