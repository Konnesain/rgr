all: rgr rgrtransposition.so rgraes.so rgrviginere.so

rgr: main.cpp
	g++ main.cpp -o rgr

rgrtransposition.so: transposition.cpp transposition.h
	g++ -shared -fPIC transposition.cpp -o rgrtransposition.so

rgrviginere.so: viginere.cpp viginere.h
	g++ -shared -fPIC viginere.cpp -o rgrviginere.so

rgraes.so: aes.cpp aes.h
	g++ -shared -fPIC aes.cpp -o rgraes.so -O1

install: all
	cp -f rgraes.so rgrviginere.so rgrtransposition.so /usr/lib/
	cp -f rgr /usr/bin/

archive: all
	tar -czf rgr.tar.gz rgr rgrtransposition.so rgrviginere.so rgraes.so

clean:
	rm -f rgraes.so rgrviginere.so rgrtransposition.so rgr rgr.tar.gz

uninstall:
	rm -f /usr/lib/rgraes.so /usr/lib/rgrtransposition.so /usr/lib/rgrviginere.so /usr/bin/rgr
