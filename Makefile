all:
	gcc sslkeylog.c -shared -o libsslkeylog.so -fPIC -ldl
	bash createCA.sh

clean:
	bash clean.sh
	rm libsslkeylog.so
	#rm premaster.txt
