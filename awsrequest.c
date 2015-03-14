#include <stdlib.h>
#include <curl/curl.h>
#include <json/json.h>
#include <stdio.h>
#include <string.h>
#include <apr-1/apr_errno.h>
#include <apr-1/apr_pools.h>
#include <apr-1/apr_tables.h>
#include <apr-1/apr_strings.h>
#include <openssl/evp.h>

static struct
{
	char access_key_id[128];
	char secret_access_key[128];
	char token[1024];
} creds;

static struct memstruct
{
	char *data;
	size_t size;
} curlmemstruct;

static size_t curl_writemem_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct memstruct *mem = (struct memstruct *)userp;

	mem->data = realloc(mem->data, mem->size + realsize + 1);

	if(mem->data == NULL)
		return 0;

	memcpy(&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	return realsize;
}

static int init_aws_creds_from_role()
{
	CURL *ch;
	json_object *credobj, *tmpobj;
	json_bool jsonret;
	CURLcode res;
	char credpath[256] = "http://169.254.169.254/2014-11-05/meta-data/iam/security-credentials/";

	// curl for the name of our credentials
	curlmemstruct.data = malloc(sizeof(char));
	*(curlmemstruct.data) = 0;
	curlmemstruct.size = 0;

	ch = curl_easy_init();
	if(!ch)
	{
		return -1;
	}

	curl_easy_setopt(ch, CURLOPT_URL, credpath);
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_writemem_callback);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, &curlmemstruct);

	res = curl_easy_perform(ch);
	if(res != CURLE_OK)
	{
		return -1;
	}

	curl_easy_cleanup(ch);

	// append the name of the creds to the creds url
	strncat(credpath, curlmemstruct.data, sizeof(credpath) - strlen(credpath) - 1);

	// curl for the actual credentials document
	free(curlmemstruct.data);
	curlmemstruct.data = malloc(sizeof(char));
	*(curlmemstruct.data) = 0;
	curlmemstruct.size = 0;

	ch = curl_easy_init();
	if(!ch)
		return -1;

	curl_easy_setopt(ch, CURLOPT_URL, credpath);
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_writemem_callback);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, &curlmemstruct);

	res = curl_easy_perform(ch);
	if(res != CURLE_OK)
		return -1;

	curl_easy_cleanup(ch);

	// parse out the relevant credential details
	credobj = json_tokener_parse(curlmemstruct.data);

	jsonret = json_object_object_get_ex(credobj, "AccessKeyId", &tmpobj);
	if(!jsonret)
		return -1;

	creds.access_key_id[0] = 0;
	strncpy(creds.access_key_id, json_object_get_string(tmpobj), sizeof(creds.access_key_id));

	jsonret = json_object_object_get_ex(credobj, "SecretAccessKey", &tmpobj);
	if(!jsonret)
		return -1;

	creds.secret_access_key[0] = 0;
	strncpy(creds.secret_access_key, json_object_get_string(tmpobj), sizeof(creds.secret_access_key));

	jsonret = json_object_object_get_ex(credobj, "Token", &tmpobj);
	if(!jsonret)
		return -1;

	creds.token[0] = 0;
	strncpy(creds.token, json_object_get_string(tmpobj), sizeof(creds.token));

	free(curlmemstruct.data);
	curlmemstruct.data = malloc(sizeof(char));
	*(curlmemstruct.data) = 0;
	curlmemstruct.size = 0;

	return 0;
}

static char *pstrtolower(apr_pool_t *pool, const char *s)
{
	char *ret = apr_pstrdup(pool, s);
	char *tmp;

	for(tmp = ret; *tmp; *tmp++)
		*tmp = tolower(*tmp);

	return ret;
}

static int _get_apr_table_keys_callback(void *data, const char *key, const char *value)
{
	apr_array_header_t *arr = data;

	*(const char **)apr_array_push(arr) = apr_pstrdup(arr->pool, key);
}

static apr_array_header_t *get_apr_table_keys(apr_pool_t *pool, apr_table_t *table)
{
	apr_array_header_t *ret = apr_array_make(pool, 16, sizeof(const char *));

	apr_table_do(_get_apr_table_keys_callback, ret, table, NULL);

	return ret;
}

static int _sort_apr_array_callback(const void *v1, const void *v2)
{
	const char *s1 = *(const char **)v1;
	const char *s2 = *(const char **)v2;

	return strcasecmp(s1, s2);
}

static void sort_apr_array(apr_array_header_t *arr)
{
	qsort(arr->elts, arr->nelts, arr->elt_size, _sort_apr_array_callback);
}

static char *psha256(apr_pool_t *pool, const char *message, size_t message_size)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;
	char *ret, *tmp;
	
	ret = apr_pcalloc(pool, (256 / 4 + 1 ) * sizeof(char));

	OpenSSL_add_all_digests();
	md = EVP_sha256();

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, message, message_size);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	for(i = 0, tmp = ret; i < md_len; i++, tmp += 2)
	{
		apr_snprintf(tmp, 3, "%02x", md_value[i]);
	}

	EVP_cleanup();

	return ret;
}

CURLcode execute_signed_aws_request(
		char **return_data,
		size_t *return_size,
		const char *method, 
		const char *hostname, 
		const char *path, 
		apr_table_t *queryparams, 
		apr_table_t *headers, 
		const char *payload, 
		size_t payload_size 
		)
{
	CURL *ch;
	CURLcode status;
	char *canonical_request;
	size_t canonical_size;
	apr_pool_t *pool;
	apr_table_t *realheaders;
	apr_status_t aprv;
	time_t now;
	apr_array_header_t *header_keys, *lower_header_keys;
	int i;
	size_t datetime_sz;
	char datetime[32];

	if(queryparams != NULL)
	{
		*return_data = strdup("Query Parameters are not supported (yet).");
		*return_size = strlen(*return_data);
		return CURLE_UNSUPPORTED_PROTOCOL;
	}

	/*
	CanonicalRequest =
	  HTTPRequestMethod + '\n' +
	  CanonicalURI + '\n' +
	  CanonicalQueryString + '\n' +
	  CanonicalHeaders + '\n' +
	  SignedHeaders + '\n' +
	  HexEncode(Hash(RequestPayload))
	*/

	aprv = apr_pool_create(&pool, NULL);
	if(aprv != APR_SUCCESS)
	{
		*return_data = "Could not create pool.";
		*return_size = strlen(*return_data);
		return CURLE_OUT_OF_MEMORY;
	}

	canonical_request = apr_pstrcat(pool,
			method, "\n",
			path, "\n",
			"", "\n",	// query string placeholder
			NULL
			);

	realheaders = apr_table_clone(pool, headers);
	if(apr_table_get(realheaders, "Host") == NULL)
	{
		apr_table_set(realheaders, "Host", hostname);
	}
	now = time(NULL);
	strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", gmtime(&now));
	apr_table_set(realheaders, "x-amz-date", datetime);

	header_keys = get_apr_table_keys(pool, realheaders);
	sort_apr_array(header_keys);

	for(i = 0; i < header_keys->nelts; i++)
	{
		canonical_request = apr_pstrcat(pool,
				canonical_request,
				pstrtolower(pool, ((const char **)header_keys->elts)[i]),
				":",
				apr_table_get(realheaders, ((const char **)header_keys->elts)[i]),
				"\n",
				NULL
				);
	}
	canonical_request = apr_pstrcat(pool, canonical_request, "\n", pstrtolower(pool, apr_array_pstrcat(pool, header_keys, ';')), "\n", psha256(pool, payload, payload_size), NULL);


	fprintf(stderr, "Canonical Request (%d/%d): [%s]\n", strlen(canonical_request), canonical_size, canonical_request);

	status = CURLE_OK;

	return status;
}

int main()
{
	int rv;
	apr_pool_t *pool;
	apr_status_t aprv;
	apr_table_t *headers, *queryparams;
	const char *payload = "Action=DescribeVPCs&Version=2014-10-01";
	CURLcode crv;
	char *result;
	size_t result_size;
	char buf[256];

	rv = init_aws_creds_from_role();

	if(rv != 0)
	{
		fprintf(stderr, "something went wrong...\n");
		return 1;
	}

	apr_initialize();

	aprv = apr_pool_create(&pool, NULL);
	if(aprv != APR_SUCCESS)
	{
		fprintf(stderr, "Could not create pool: %s\n", apr_strerror(aprv, buf, sizeof(buf)));
		return 1;
	}

	queryparams = NULL;

	headers = apr_table_make(pool, 16);
	apr_table_set(headers, "Content-Type", "application/x-www-form-urlencoded");

	crv = execute_signed_aws_request(
			&result,
			&result_size,
			"POST",
			"ec2.us-east-1.amazonaws.com",
			"/",
			NULL,
			headers,
			payload,
			strlen(payload)
			);

	apr_terminate();

	return 0;
}
