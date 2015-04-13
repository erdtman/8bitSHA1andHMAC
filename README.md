# 8 bit SHA1 and HMAC
This is a 8 bit implementation of SHA1 and HMAC, it uses unsigned char and unsigned char arrays for everything. It was ment to be ported one step further to run on a TWN/TWN3/TWN4 RFID reader, but the memory footprint was to large for the versions tested.

## Compile
```
ggc test.c -o test.o
```