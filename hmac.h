#ifndef HMAC_H
#define HMAC_H

#include "sha1.h"

#ifndef byte
	#define byte unsigned char
#endif

void hmac(byte* key, byte keylen, byte* msg, byte msglen, byte* out) {
	byte ipad = 0x36;
	byte opad = 0x5C;
	byte padded_key[64];
	byte internal_msg[128]; // we will not manage big texts
	byte t;
	byte digest[20];
	
	for (t=0; t<64; t++){
		if(t<keylen) {
			padded_key[t] = key[t];
		} else {
			padded_key[t] = 0;
		}
		internal_msg[t] = padded_key[t];
		internal_msg[t] ^= ipad;
	}

	for (t=0; t<msglen; t++) {
		internal_msg[64+t] = msg[t];
	}

	sha1(internal_msg, 64+msglen, digest);

	for (t=0; t<64;t++){
		internal_msg[t] = padded_key[t];
		internal_msg[t] ^= opad;
	}

	for (t=0; t<20; t++) {
		internal_msg[64+t] = digest[t];
	}

	sha1(internal_msg, 64+20, out);
}

#endif