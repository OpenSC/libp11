#include <stdio.h>
#include <libp11.h>

int main(int argc, char **argv)
{
	PKCS11_CTX *ctx;
        PKCS11_SLOT *slot;
	unsigned char random[10];
	int rc,len;

	ctx = PKCS11_CTX_new();

        /* load pkcs #11 module */
        rc = PKCS11_CTX_load(ctx, "/home/aj/opensc/lib/opensc-pkcs11.so");
        if (rc) {
                fprintf(stderr, "loading pkcs11 engine failed\n");
		rc=1;
		goto nolib;
        }

        /* get first slot with a token */
        slot = PKCS11_find_token(ctx);
        if (!slot || !slot->token) {
                fprintf(stderr, "no token available\n");
                rc=2;
                goto noslot;
        }

	/* get 10 random bytes */
	len=sizeof(random);
	rc = PKCS11_generate_random(slot, random, len);
	if (rc < 0) {
		fprintf(stderr,"generate_random failed: %d\n",rc);
		rc=3;
		goto norandom;
	}

	printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		random[0], random[1], random[2], random[3], random[4], 
		random[5], random[6], random[7], random[8], random[9]); 

	rc=0;
norandom:
noslot:
        PKCS11_CTX_unload(ctx);
nolib:
	PKCS11_CTX_free(ctx);
	return rc;
}
