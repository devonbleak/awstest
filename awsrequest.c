#include <curl/curl.h>
#include <json/json.h>
#include <apr-1/apr_errno.h>
#include <apr-1/apr_pools.h>
#include <apr-1/apr_tables.h>
#include <apr-1/apr_strings.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// aws credentials
static struct
{
	char access_key_id[128];
	char secret_access_key[128];
	char token[1024];
} creds;

// buffer for capturing curl responses
static struct memstruct
{
	char *data;
	size_t size;
} curlmemstruct;

// callback for capturing curl responses in memory
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

// use EC2 instance metadata to get temporary AWS credentials
int init_aws_creds_from_role()
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
	json_object_put(tmpobj);

	jsonret = json_object_object_get_ex(credobj, "SecretAccessKey", &tmpobj);
	if(!jsonret)
		return -1;

	creds.secret_access_key[0] = 0;
	strncpy(creds.secret_access_key, json_object_get_string(tmpobj), sizeof(creds.secret_access_key));
	json_object_put(tmpobj);

	jsonret = json_object_object_get_ex(credobj, "Token", &tmpobj);
	if(!jsonret)
		return -1;

	creds.token[0] = 0;
	strncpy(creds.token, json_object_get_string(tmpobj), sizeof(creds.token));
	json_object_put(tmpobj);

	json_object_put(credobj);
	free(curlmemstruct.data);

	return 0;
}

// create a new copy of s from pool and return it lower-cased
static char *pstrtolower(apr_pool_t *pool, const char *s)
{
	char *ret = apr_pstrdup(pool, s);
	char *tmp;

	for(tmp = ret; *tmp; *tmp++)
		*tmp = tolower(*tmp);

	return ret;
}

// callback for getting apr_table_t * keys
static int _get_apr_table_keys_callback(void *data, const char *key, const char *value)
{
	apr_array_header_t *arr = data;

	*(const char **)apr_array_push(arr) = apr_pstrdup(arr->pool, key);

	return 1;
}

// return all the keys from an apr_table_t * as an apr_array_header_t *
static apr_array_header_t *get_apr_table_keys(apr_pool_t *pool, apr_table_t *table)
{
	apr_array_header_t *ret = apr_array_make(pool, 16, sizeof(const char *));

	apr_table_do(_get_apr_table_keys_callback, ret, table, NULL);

	return ret;
}

// combo of an apr memory pool and curl_slist
static struct {
	apr_pool_t *pool;
	struct curl_slist *slist;
} pool_slist;

// convert apr_table into curl slist for setting HTTP headers
static int _header_table_to_slist_callback(void *data, const char *key, const char *value)
{
	pool_slist.slist = curl_slist_append(pool_slist.slist, apr_pstrcat(pool_slist.pool, key, ": ", value, NULL));

	return 1;
}

// callback for sorting apr_array_header_t * in place - dereference and compare
static int _sort_apr_array_case_callback(const void *v1, const void *v2)
{
	// dereference the strings to compare
	const char *s1 = *(const char **)v1;
	const char *s2 = *(const char **)v2;

	// return the case-insensitive comparison
	return strcasecmp(s1, s2);
}

// sort an apr_array_header_t * in place
static void sort_apr_array_case(apr_array_header_t *arr)
{
	qsort(arr->elts, arr->nelts, arr->elt_size, _sort_apr_array_case_callback);
}

// calculate sha256 hash and hex-encode into a pool-allocated buffer
static char *psha256hex(apr_pool_t *pool, const char *message, size_t message_size)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;
	char *ret, *tmp;
	
	ret = apr_pcalloc(pool, (256 / 4 + 1 ) * sizeof(char));

	// calculate the hash
	OpenSSL_add_all_digests();
	md = EVP_sha256();

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, message, message_size);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	// hex encode the output
	for(i = 0, tmp = ret; i < md_len; i++, tmp += 2)
		apr_snprintf(tmp, 3, "%02x", md_value[i]);

	EVP_cleanup();

	return ret;
}

CURLcode execute_signed_aws_request(
		char **return_data,
		size_t *return_size,
		const char *method, 
		const char *service,
		const char *region,
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
	char *canonical_request, *signed_headers, *string_to_sign, *request_signature, *tmpcp;
	apr_pool_t *pool;
	apr_table_t *realheaders;
	apr_status_t aprv;
	time_t now;
	apr_array_header_t *header_keys, *lower_header_keys;
	int i, md_len;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	size_t datetime_sz;
	char datetime[32], today[9];

	// make sure we have no query params
	if(queryparams != NULL)
	{
		*return_data = strdup("Query Parameters are not supported (yet).");
		*return_size = strlen(*return_data);
		return CURLE_UNSUPPORTED_PROTOCOL;
	}

	// create a memory pool
	aprv = apr_pool_create(&pool, NULL);
	if(aprv != APR_SUCCESS)
	{
		*return_data = "Could not create pool.";
		*return_size = strlen(*return_data);
		return CURLE_OUT_OF_MEMORY;
	}

	// build the canonical request
	/*
	CanonicalRequest =
	  HTTPRequestMethod + '\n' +
	  CanonicalURI + '\n' +
	  CanonicalQueryString + '\n' +
	  CanonicalHeaders + '\n' +
	  SignedHeaders + '\n' +
	  HexEncode(Hash(RequestPayload))
	*/
	canonical_request = apr_pstrcat(pool,
			method, "\n",
			path, "\n",
			"", "\n",	// query string placeholder
			NULL
			);

	// make a copy of the headers since we're going to add some of our own
	realheaders = apr_table_clone(pool, headers);
	apr_table_set(realheaders, "Host", hostname);

	// calculate datetime
	now = time(NULL);
	strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", gmtime(&now));
	apr_table_set(realheaders, "x-amz-date", datetime);

	// add canonical headers
	header_keys = get_apr_table_keys(pool, realheaders);
	sort_apr_array_case(header_keys);

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

	// add signed headers and payload hash
	signed_headers = pstrtolower(pool, apr_array_pstrcat(pool, header_keys, ';'));
	canonical_request = apr_pstrcat(pool, canonical_request, "\n", signed_headers, "\n", psha256hex(pool, payload, payload_size), NULL);

	// build string to sign
	apr_snprintf(today, 9, "%s", datetime);
	string_to_sign = apr_pstrcat(pool,
			"AWS4-HMAC-SHA256\n",
			datetime, "\n",
			today, "/", region, "/", service, "/aws4_request\n",
			psha256hex(pool, canonical_request, strlen(canonical_request)),
			NULL
			);

	// build our signing key
	/*
	 * kSecret = Your AWS Secret Access Key
	 * kDate = HMAC("AWS4" + kSecret, Date)
	 * kRegion = HMAC(kDate, Region)
	 * kService = HMAC(kRegion, Service)
	 * kSigning = HMAC(kService, "aws4_request")
	 */
	HMAC(EVP_sha256(),
			apr_pstrcat(pool, "AWS4", creds.secret_access_key, NULL), strlen(creds.secret_access_key) + 4,
			today, 8,
			md_value, &md_len
		);
	HMAC(EVP_sha256(),
			md_value, md_len,
			region, strlen(region),
			md_value, &md_len
		);
	HMAC(EVP_sha256(),
			md_value, md_len,
			service, strlen(service),
			md_value, &md_len
		);
	HMAC(EVP_sha256(),
			md_value, md_len,
			"aws4_request", strlen("aws4_request"),
			md_value, &md_len
		);
	
	// calculate the request signature
	// signature = HexEncode(HMAC(derived-signing-key, string-to-sign))
	HMAC(EVP_sha256(),
			md_value, md_len,
			string_to_sign, strlen(string_to_sign),
			md_value, &md_len
		);

	request_signature = apr_pcalloc(pool, 2 * md_len + 1);
	for(i = 0, tmpcp = request_signature; i < md_len; i++, tmpcp += 2)
		apr_snprintf(tmpcp, 3, "%02x", md_value[i]);

	// build our authorization header
	apr_table_set(realheaders, "Authorization", apr_pstrcat(pool,
				"AWS4-HMAC-SHA256 Credential=",
				creds.access_key_id, "/", today, "/", region, "/", service, "/aws4_request, ",
				"SignedHeaders=", signed_headers, ", ",
				"Signature=", request_signature,
				NULL
				)
			);

	// if we're using temp creds add the token
	if(strlen(creds.token))
		apr_table_set(realheaders, "X-Amz-Security-Token", creds.token);

	// build the actual request
	ch = curl_easy_init();
	curl_easy_setopt(ch, CURLOPT_URL, apr_pstrcat(pool, "https://", hostname, path, NULL));

	// for now treat everything like a POST
	curl_easy_setopt(ch, CURLOPT_POST, 1L);
	curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, method);
	if(payload_size != 0)
	{
		curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, payload_size);
		curl_easy_setopt(ch, CURLOPT_POSTFIELDS, payload);
	}

	// set request headers
	pool_slist.pool = pool;
	pool_slist.slist = NULL;
	apr_table_do(_header_table_to_slist_callback, NULL, realheaders, NULL);
	curl_easy_setopt(ch, CURLOPT_HTTPHEADER, pool_slist.slist);

	// capture the output in curlmemstruct
	curlmemstruct.data = malloc(sizeof(char));
	curlmemstruct.size = 0;

	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_writemem_callback);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, &curlmemstruct);

	// execute the request
	status = curl_easy_perform(ch);

	// copy results to a fresh non-static buffer
	*return_data = calloc(curlmemstruct.size, 1);
	memcpy(*return_data, curlmemstruct.data, curlmemstruct.size);
	*return_size = curlmemstruct.size;

	// clean up
	curl_slist_free_all(pool_slist.slist);
	curl_easy_cleanup(ch);
	free(curlmemstruct.data);
	curlmemstruct.data = malloc(sizeof(char));
	curlmemstruct.size = 0;
	apr_pool_destroy(pool);

	return status;
}

