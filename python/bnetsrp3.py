#!/usr/bin/env python
# coding: utf8

# 30.08.11 
# edited 09.11.12
# @author xpeh
# @version 1.3
#
# calculates Warcraft 3 Battle.Net & pvpgn 1.99.x SRP hash (verifier)
#
# check the latest version at http://forums.harpywar.com/viewtopic.php?id=564

from hashlib import sha1
import sys, os

N = 0xF8FF1A8B619918032186B68CA092B5557E976C78C73212D91216F6658523C787
g = 47

def usage():
    print "usage: %s username password [32 byte salt as hex]" % os.path.basename(sys.argv[0])
    sys.exit(1)

def intToBuf(int, size=32):
    '''Returns at least size bytes
    '''
    hexstr = "%x" % int
    length = len(hexstr)
    if length < size*2:
        hexstr = ("0"*(size*2-length) + hexstr)
    elif length % 2 != 0:
        hexstr = ("0" + hexstr)
    return hexstr.decode('hex')

def bufToInt(buf):
    return int(buf.encode('hex'),16)
    
def srp_hash(username, password, salt):
    # x = reverse_bytes( sha1(salt, sha1(upper(username),":", upper(password))) )
    x = sha1(salt + sha1(username.upper() + ":" + password.upper()).digest()).digest()
    # [::-1] means reverse bytes in buffer
    print 'password hash:', x[::-1].encode('hex')
    x = bufToInt(x[::-1])

    # verifier = reverse_bytes(g^x % N)
    verifier = pow(g, x, N)
    verifier = intToBuf(verifier)[::-1]
    return verifier

    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    username = sys.argv[1]
    password = sys.argv[2]

    if len(sys.argv) >= 4:
        salt = sys.argv[3]
        salt = salt.replace(" ","").decode('hex')
    else:
        # random salt
        salt = os.urandom(32)

    print "salt     :", salt.encode('hex')
    verifier = srp_hash(username, password, salt)
    print "verifier :", verifier.encode('hex')
