PORT=7891
all: gcmtest hashtest server-test client-test
server-test: hash.o encdec.o srp.o test-srp-server.o libtommath/libtommath.a
	cc -o server-test hash.o srp.o encdec.o test-srp-server.o libtommath/libtommath.a
client-test: hash.o encdec.o srp.o test-srp-client.o libtommath/libtommath.a
	cc -o client-test hash.o srp.o encdec.o test-srp-client.o libtommath/libtommath.a
srptest: hash.o srp.o libtommath/libtommath.a
	cc -o srptest hash.o srp.o libtommath/libtommath.a
gcmtest: encdec.o test-gcm.o
	cc -o gcmtest encdec.o test-gcm.o
hashtest: hash.o test-hash.o
	cc -o hashtest hash.o test-hash.o
.c.o:
	cc -c -DPORT=${PORT} -Wall $<
srp.o:
	cc -c -Wall srp.c
clean:
	rm *.o *~
