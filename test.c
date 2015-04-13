#include <stdio.h>
#include <string.h>

#include "sha1.h"
#include "hmac.h"

#ifndef byte
	#define byte unsigned char
#endif

void printArray(byte msg[]) {
  byte n ;
  for(byte k = 0; k<4; k++) {
  	n = msg[k];
    for(byte i = 7; i>=0; i--) {
      if ((n>>i) & 1){
        printf("1");
      } else {
        printf("0");
      }
    }
    printf("");
  }
}

void printHex(byte msg[], byte length){
	printf("0x");
	for(byte i=0; i<length; i++){
		if (msg[i]>0x0f){
			printf("%x", msg[i]);
		} else {
			printf("0%x", msg[i]);
		}		
	}
	printf("\n");
}

int main() {
  byte digest[20];

  printf("SHA1\n");
  char* input_1 = "";
  byte len_1 = 0;
  printf("0xda39a3ee5e6b4b0d3255bfef95601890afd80709\n");
  sha1((const byte *) input_1, len_1, digest);
  printHex(digest, 20); printf("\n");

  char* input_2 = "abc";
  byte len_2 = 3; 
  printf("0xa9993e364706816aba3e25717850c26c9cd0d89d\n");
  sha1((const byte *) input_2, len_2, digest);
  printHex(digest, 20); printf("\n");

  char* input_3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  byte len_3 = 56;
  printf("0x84983e441c3bd26ebaae4aa1f95129e5e54670f1\n");
  sha1((const byte *) input_3, len_3, digest);
  printHex(digest, 20); printf("\n");

  char* input_4 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  byte len_4 = 112;
  printf("0xa49b2446a02c645bf419f995b67091253a04a259\n");
  sha1((const byte *) input_4, len_4, digest);
  printHex(digest, 20); printf("\n");



  printf("HMAC-SHA1\n");
  byte key_1[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  byte keylen_1 = 20;
  byte data_1[] = "Hi There";
  byte datalen_1 = 8;
  printf("0xb617318655057264e28bc0b6fb378c8ef146be00\n");
  hmac(key_1, keylen_1, data_1, datalen_1, digest);
  printHex(digest, 20); printf("\n");

  byte key_2[] = "Jefe";
  byte keylen_2 = 4;
  byte data_2[] = "what do ya want for nothing?";
  byte datalen_2 = 28;
  printf("0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79\n");
  hmac(key_2, keylen_2, data_2, datalen_2, digest);
  printHex(digest, 20); printf("\n");

  byte key_3[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
  byte keylen_3 = 20;
  byte data_3[] = {0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd};
  byte datalen_3 = 50;
  printf("0x125d7342b9ac11cd91a39af48aa17b4f63f175d3\n");
  hmac(key_3, keylen_3, data_3, datalen_3, digest);
  printHex(digest, 20); printf("\n");

  byte key_4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  byte keylen_4 = 25;
  byte data_4[] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
  byte datalen_4 = 50;
  printf("0x4c9007f4026250c6bc8414f9bf50c86c2d7235da\n");
  hmac(key_4, keylen_4, data_4, datalen_4, digest);
  printHex(digest, 20); printf("\n");

  return 0;
}
  
