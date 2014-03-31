#include "deobfuscate.h"
#include <stdlib.h>

// Returned pointer pointer must be freed by the caller
// Al momento le free() non vengono MAI chiamate perche' tutti i comandi sono one-shot
// E' zozza ma almeno non triplichiamo tutte le righe di codice e cmq il processo non
// resta mai attivo.
unsigned char* deobfuscate(unsigned char *s) {
    unsigned char key, mod, len;
    int i, j;
	unsigned char* d;
	
    key = s[0];
    mod = s[1];
    len = s[2] ^ key ^ mod;

	d = (unsigned char *)malloc(len + 1);
	
    // zero terminate the string
    memset(d, 0x00, len + 1);

    for (i = 0, j = 3; i < len; i++, j++) {
        d[i] = s[j] ^ mod;
        d[i] -= mod;
        d[i] ^= key;
    }

    d[len] = 0;
	
    return d;
}
