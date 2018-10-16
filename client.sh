SSLKEYLOGFILE=premaster.txt LD_PRELOAD=./libsslkeylog.so openssl s_client -connect 127.0.0.1:2018 -debug
