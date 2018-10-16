# Setup
`make`

Enter no data during the certification creation process, just press ENTER.

```
./dumper.sh (as root)
run ./server.sh in a different shell
run ./client.sh in a different shell
```
Then send in the client shell for example:
SECRET DATA SHARED

Then stop all software:
```
kill client with CTRL+C
kill server with CTRL+C
stop listening and CTRL+C dumper
```
you should have now everything you need to decrypt traffic:

`./decrypt.py`

END

# Notes

You can try to use chromium with 'chromium ssl-key-log-file="premaster.txt"', but you will have to need all ciphers.
I recommend for testing cipher stuff a custom openssl build, containing all you need.

pcap with the connection
premaster client keys in premaster.txt
server private key (makes decryption very easy, but we want to use the client keys)

The file openssl.Linux.x86_64 is borrowed from testssl.sh project, it contains all ciphers (especially the weak ones) and is useful for testing.

The file sslkeylog.c is from Peter Wu.

# Dependencies

* Scapy and TLS/SSL Extension
* Python 2.7 or higher, but Python2 branch, no 3!
* openssl (you can also use the delivered binary (default), it is from testssl.sh project)
* python Crypto
* hmac, hashlib, binascii should be in standard python2 installation
* tcpdump -> run dumper.sh as root!
* bash shell is called in some scripts. This can be changed easily if you don't have bash
