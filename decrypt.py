#!/usr/bin/env python2

"""
Decrypt the TLS Application Data PoC:

Some functions are from here (origin is PHP and RC4):
https://github.com/jaytaph/TLS-decoder

And an interesting guide is here:
https://lowleveldesign.org/2016/03/09/manually-decrypting-https-request/

But mainly was used this:
https://www.ietf.org/rfc/rfc5246.txt
https://git.lekensteyn.nl/peter/wireshark-notes/tree/src/sslkeylog.c

And the most valueable ressource:
Wireshark debug file.
In this debug file it is easy possible to see through the decryption process.

The functions prf_tls12 and p_hash are from the specification,
inspired by PHP/RC4 approach and generate_keys is basically a wrapper.
"""

from __future__ import with_statement
from __future__ import print_function
from scapy.layers.ssl_tls import *

import hmac
import hashlib
import binascii
from Crypto.Cipher import AES
import scapy

def generate_keys(master_secret, client_random, server_random):
    # for aes 256 cbc we need 136 bytes, see the debug file for more information
    return prf_tls12(master_secret, 'key expansion', server_random + client_random, 136);
    
def prf_tls12(secret, label, seed, size):
    return p_hash(secret, label + seed, size);

"""

   rfc5246.txt, page 14/15

   First, we define a data expansion function, P_hash(secret, data),
   that uses a single hash function to expand a secret and seed into an
   arbitrary quantity of output:
   
   
   
    P_hash(secret, seed) =   HMAC_hash(secret, A(1) + seed) +
                             HMAC_hash(secret, A(2) + seed) +
                             HMAC_hash(secret, A(3) + seed) + ...

   where + indicates concatenation.

   A() is defined as:

      A(0) = seed
      A(i) = HMAC_hash(secret, A(i-1))

   P_hash can be iterated as many times as necessary to produce the
   required quantity of data.  For example, if P_SHA256 is being used to
   create 80 bytes of data, it will have to be iterated three times
   (through A(3)), creating 96 bytes of output data; the last 16 bytes
   of the final iteration will then be discarded, leaving 80 bytes of
   output data.

   TLS's PRF is created by applying P_hash to the secret as:

      PRF(secret, label, seed) = P_<hash>(secret, label + seed)
      
   The most interesting part:
   For the decryption, we need a seed.
   This seed is label + server_random + client_random,
   where label is in our case 'key expansion'.
   
   This label changes for other stages in the protocol, for example
   it is 'master secret' for the master secret calculation.
   We do not need this at this point, because we already have it through the LD_PRELOAD sslkeylogfile.c Hack.
"""

def p_hash(secret, seed, size):
    output = b''
    a = seed
    while len(output) < size:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        output = output + hmac.new(secret, a + seed, hashlib.sha256).digest()
    return output[0:size]

#
# scapy identifies tls traffic not automatically, you have to specify ports:
#
bind_layers(TCP, SSL, dport=2018)
bind_layers(TCP, SSL, sport=2018)
scapy_cap = rdpcap('com.pcap')

print("+--------------------------------------------------------+")
print("| TLS Application Data decryption proof of concept       |")
print("| print the decrypted application data                   |")
print("| It works if it prints \'SECRET DATA SHARED\'             |")
print("| not every byte is printable, we print the hmac etc. too|")
print("+--------------------------------------------------------+\n")


#
# data to decrypt
#

client_random = b'' #binascii.unhexlify("62082ed192e4150990f2aff21073311f37096e924b0dda566d85e28e322ebde6")
server_random = b'' #binascii.unhexlify("95efb10ddb251fdd5fa81b11fd965561cd397493f2661b6dbaa3277cc939105c")
master_secret = b'' #binascii.unhexlify("C5E037C94CE2B754D3368EDC7FDDAC4518732DF86534D5E5A739B40EE6D3AFDE98C0DA5E9B17C4E05A2F8921BD9A8802")
tls_app_data = b''  #binascii.unhexlify("edc5716d505b368615a3da20d210fe324c3857b66692f931e5aa18f9dc7b42d6ad053b2775184bbabf3fcd7dd06894f12c2106cb72d0faa2fb8818e4dd283c0e")


#
# Get the master secret from the premaster.txt
# Since this is PoC, it works only with a single line/uses only the last line
#

for i in open('premaster.txt'):
    if "CLIENT_RANDOM" in i:
        # dirty hack but we are in fixed length world:
        master_secret = binascii.unhexlify(i[79:175])

for pkt in scapy_cap:
    if pkt.haslayer(SSL):
        if pkt.haslayer(TLSHandshake):
            #
            # Get the client_random
            #
            if pkt[TLSHandshake].type == 1:
                cr =  str(hex((pkt[TLSClientHello].gmt_unix_time)))[2:] + str(binascii.hexlify(pkt[TLSClientHello].random_bytes))
                client_random = binascii.unhexlify(cr)
            #
            # Get the server_random
            #
            if pkt[TLSHandshake].type == 2:
                sr =  str(hex((pkt[TLSServerHello].gmt_unix_time)))[2:] + str(binascii.hexlify(pkt[TLSServerHello].random_bytes))
                server_random = binascii.unhexlify(sr)
        
        #
        # Extract the TLS Application Data
        #
        if pkt.haslayer(TLSRecord):
            if pkt.haslayer(TLSCiphertext):
                tls_app_data = pkt[TLSCiphertext].data

print("master_secret: " + binascii.hexlify(master_secret))
print("client_random: " + binascii.hexlify(client_random))
print("server_random: " + binascii.hexlify(server_random))
print("tls app data:  " + binascii.hexlify(tls_app_data))
print("\n")


#
# Build the keys for decryption of AES CBC:
# The structure/sizes are copied from wireshark debug file.
#

key_buffer = generate_keys(master_secret, client_random, server_random)
client_mac_key = key_buffer[0:20]
server_mac_key = key_buffer[20:40]
client_write_key = key_buffer[40:72]
server_write_key = key_buffer[72:104]
client_write_iv = key_buffer[104:120]
server_write_iv = key_buffer[120:136]


#
# Decrypt with AES.
# GCM works apperantly not with this library in the version I use.
# So I stay with CBC support only -> Reminder: PoC only. Not so cool as it could be.
#
# It prints the hmac and other stuff in the application data.
# A correct implementation would obviously validate the hmac.
# This one is just printing everything, a nicer output would require
# to parse the application data structure as mentioned in the rfc
#
aes = AES.new(client_write_key, AES.MODE_CBC, client_write_iv)
print("TLS Application Data: \n")
print(aes.decrypt(tls_app_data))
