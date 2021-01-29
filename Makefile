srptest: hash.o srp.o libtommath/libtommath.a
	cc -o a.out hash.o srp.o libtommath/libtommath.a
.c.o:
	cc -c -Wall $<
srp.o:
	cc -c -Wall -D TEST_SRP srp.c
clean:
	rm *.o *~
