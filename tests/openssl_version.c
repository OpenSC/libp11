/*
 * Feel free to copy all of the code as needed.
 */

#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

int main()
{
	puts(OPENSSL_VERSION_TEXT);
	return 0;
}

/* vim: set noexpandtab: */
