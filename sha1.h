#ifndef SHA1_H
#define SHA1_H


#ifndef byte
	#define byte unsigned char
#endif


void SHA1CircularShift(byte bits, byte number[], byte out[]) {
  byte in[4];

  in[0] = number[0];
  in[1] = number[1];
  in[2] = number[2];
  in[3] = number[3];

  byte shift = bits;
  for(byte t=1; t<5; t++) {
	  if (bits > (8*(t))) { // 8, 16, 24, 32
	  	shift = 8;
	  } else {
	  	shift = bits - (8*(t-1)); // 0, 8, 16, 24
	  } 

	  out[0] = (in[0] << shift) | (in[1] >> (8 - shift)); 
	  out[1] = (in[1] << shift) | (in[2] >> (8 - shift));
	  out[2] = (in[2] << shift) | (in[3] >> (8 - shift));
	  out[3] = (in[3] << shift) | (in[0] >> (8 - shift));

	  if (bits <= (8*t)) { // 8, 16, 24, 32
	  	return;
	  }

	  in[0] = out[0];
	  in[1] = out[1];
	  in[2] = out[2];
	  in[3] = out[3];
  }
}

void or(byte first[], byte second[], byte out[]) {
	out[0] = first[0] | second[0];
	out[1] = first[1] | second[1];
	out[2] = first[2] | second[2];
	out[3] = first[3] | second[3];
}

void and(byte first[], byte second[], byte out[]) {
	out[0] = first[0] & second[0];
	out[1] = first[1] & second[1];
	out[2] = first[2] & second[2];
	out[3] = first[3] & second[3];
}

void xor(byte first[], byte second[], byte out[]) {
	out[0] = first[0] ^ second[0];
	out[1] = first[1] ^ second[1];
	out[2] = first[2] ^ second[2];
	out[3] = first[3] ^ second[3];
}

void comp(byte first[], byte out[]) {
	out[0] = ~first[0];
	out[1] = ~first[1];
	out[2] = ~first[2];
	out[3] = ~first[3];
}

void assign(byte dest[], byte source[]) {
	dest[0] = source[0];
	dest[1] = source[1];
	dest[2] = source[2];
	dest[3] = source[3];
}

void sum(byte first[], byte second[], byte out[]) {
	byte overflow = 0;
	byte temp[] = {0x0, 0x0, 0x0, 0x0};

	temp[3] = first[3] + second[3];
    
	if (first[3] >= (256-second[3])) {
		overflow = 1;
	}
	temp[2] = first[2] + second[2] + overflow;


	if (first[2] >= (256-(second[2] + overflow))) {
		overflow = 1;
	} else {
		overflow = 0;
	}
	temp[1] = first[1] + second[1] + overflow;

	
	if (first[1] >= (256-(second[1] + overflow))) {
		overflow = 1;
	} else {
		overflow = 0;
	}
	temp[0] = first[0] + second[0] + overflow;

	assign(out, temp);
}



void processBlock(byte old[], byte out[], byte message_block[]){
	byte K0[] = {0x5A, 0x82, 0x79, 0x99};
	byte K1[] = {0x6E, 0xD9, 0xEB, 0xA1};
	byte K2[] = {0x8F, 0x1B, 0xBC, 0xDC};
	byte K3[] = {0xCA, 0x62, 0xC1, 0xD6};

	byte A[] = {0x0,0x0,0x0,0x0};
	byte B[] = {0x0,0x0,0x0,0x0};
	byte C[] = {0x0,0x0,0x0,0x0};
	byte D[] = {0x0,0x0,0x0,0x0};
	byte E[] = {0x0,0x0,0x0,0x0};
	byte temp[4];
	byte temp2[4];
	byte W[80*4];	// TODO clear
	byte t;
	
	for(t=0; t<80; t++) {
    	assign(&W[(t*4)], A);
    }

    for (t = 0; t < 64; t++) {
        W[t] = message_block[t];
    }
    
    for(t=16; t < 80; t++) {
    	// W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    	xor(&W[t*4 - 3*4], &W[t*4 - 8*4], temp); // temp = W[t-3] ^ W[t-8]
    	xor(temp, &W[t*4 - 14*4], temp); // temp = W[t-3] ^ W[t-8] ^ W[t-14]
    	xor(temp, &W[t*4 - 16*4], temp); // temp = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
    	SHA1CircularShift(1, temp, &W[(t*4)]); // W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    assign(A, &old[0]); // A = context->Intermediate_Hash[0];
    assign(B, &old[4]); // B = context->Intermediate_Hash[1];
    assign(C, &old[8]); // C = context->Intermediate_Hash[2];
    assign(D, &old[12]); // D = context->Intermediate_Hash[3];
    assign(E, &old[16]); // E = context->Intermediate_Hash[4];

    for (t=0; t < 80; t++) {
    	if (t<20) {
    		// temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
	        and(B, C, temp); // temp = (B & C)
			comp(B, temp2); // temp2 = ~B
			and(temp2, D, temp2); // temp2 = (~B) & D
			or(temp, temp2, temp); // temp = (B & C) | ((~B) & D)
			SHA1CircularShift(5, A, temp2);
			sum(temp, temp2, temp); // temp = SHA1CircularShift(5, A) + (B & C) | ((~B) & D)
			sum(temp, E, temp); // temp = SHA1CircularShift(5, A) + (B & C) | ((~B) & D) + E
			sum(temp, &W[t*4], temp); // temp = SHA1CircularShift(5, A) + (B & C) | ((~B) & D) + E + W[t]
			sum(temp, K0, temp); // temp = SHA1CircularShift(5, A) + (B & C) | ((~B) & D) + E + W[t] + K[0]
    	} else if (t<40){
    		// temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
    		SHA1CircularShift(5,A, temp); // temp = SHA1CircularShift(5,A)
	        xor(B, C, temp2); // temp2 = B ^ C
	        xor(temp2, D, temp2); // temp2 = B ^ C ^ D
	        sum(temp, temp2, temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D)
	        sum(temp, E, temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E
	        sum(temp, &W[t*4], temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t]
	        sum(temp, K1, temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3]
    	} else if (t<60){
    		//temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
	        and(B, C, temp); // temp = B & C
	        and(B, D, temp2); // temp2 = B & D
	        or(temp, temp2, temp); // temp = (B & C) | (B & D)
	        and(C, D, temp2); // temp2 = C & D
	        or(temp, temp2, temp2); // temp2 = (B & C) | (B & D) | (C & D)
	        SHA1CircularShift(5, A, temp); // temp = SHA1CircularShift(5,A)
	        sum(temp, temp2, temp); // temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D))
	        sum(temp, E, temp); // temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E
	        sum(temp, &W[t*4], temp); // temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t]
	        sum(temp, K2, temp); // temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K2
    	} else if (t<80) {
    		// temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
	        SHA1CircularShift(5,A, temp); // temp = SHA1CircularShift(5,A)
	        xor(B, C, temp2); // temp2 = B ^ C
	        xor(temp2, D, temp2); // temp2 = B ^ C ^ D
	        sum(temp, temp2, temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D)
	        sum(temp, E, temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E
	        sum(temp, &W[t*4], temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t]
	        sum(temp, K3, temp); // temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3] 
    	}

    	assign(E, D); //E = D;
        assign(D, C); //D = C;
        SHA1CircularShift(30, B, C); //C = SHA1CircularShift(30,B);
        assign(B, A); // B = A;
        assign(A, temp); // A = temp;
    }

    sum(A, &old[0], &out[0]); // context->Intermediate_Hash[0] += A;
    sum(B, &old[4], &out[4]); // context->Intermediate_Hash[1] += B;
    sum(C, &old[8], &out[8]); // context->Intermediate_Hash[2] += C;
    sum(D, &old[12], &out[12]); // context->Intermediate_Hash[3] += D;
    sum(E, &old[16], &out[16]); // context->Intermediate_Hash[4] += E;
}

void sha1(const byte message[], byte length, byte out[]) {
	byte old[] = {0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x98,0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0};
	byte lenght_low = 0;
	byte lenght_high = 0;
	byte index = 0;
	byte message_block[64];

	for(byte i = 0; i<length; i++) {
        message_block[index++] = message[i];

        lenght_low += 8;
        if (lenght_low == 0) {
            lenght_high++;
        }

        if (index == 64) {
        	processBlock(old, out, message_block);
        	for (byte i=0; i<20; i++){
        		old[i] = out[i];
        	}

        	index = 0;
        }
    }

    message_block[index++] = 0x80;
    if (index > 55) {
        while (index < 64) {
            message_block[index++] = 0;
        }

        processBlock(old, out, message_block);
       	for (byte i=0; i<20; i++){
       		old[i] = out[i];
       	}
        index = 0;
    }

    while (index < 62) {
        message_block[index++] = 0;
    }
    
    message_block[62] = lenght_high;
    message_block[63] = lenght_low;

    processBlock(old, out, message_block);
}

#endif