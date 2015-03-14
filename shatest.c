#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main()
{
	const char message[] = "";
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;

	OpenSSL_add_all_digests();

	md = EVP_sha256();

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	for(i = 0; i < md_len; i++)
	{
		fprintf(stderr, "%02x", md_value[i]);
	}
	fprintf(stderr, "\n");

	EVP_cleanup();

	return 0;
}
