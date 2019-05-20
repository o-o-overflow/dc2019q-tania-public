tania: tania.c consts.h
	gcc -o tania -Wall -fPIC -pie -Wl,-z,relro,-z,now tania.c -lgmp -lcrypto
	strip -s tania

strip: tania
	strip -s tania

serve:
	socat TCP-LISTEN:31337,reuseaddr,fork,bind=localhost exec:"./tania"

clean:
	rm tania
