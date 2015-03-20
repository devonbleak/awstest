#include "awsrequest.h"
#include <stdio.h>
#include <apr-1/apr_tables.h>
#include <apr-1/apr_errno.h>
#include <apr-1/apr_base64.h>
#include <json/json.h>

int main()
{
	int rv;
	apr_pool_t *pool;
	apr_status_t aprv;
	apr_table_t *headers, *queryparams;
	const char *payload = "{\"CiphertextBlob\":\"CiDSrhDgQeTnNqFX3qXI7jrxecTzKRwJrFZ428NieT2zGRKTAQEBAgB40q4Q4EHk5zahV96lyO468XnE8ykcCaxWeNvDYnk9sxkAAABqMGgGCSqGSIb3DQEHBqBbMFkCAQAwVAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAx6HP9tsdd3bjxX2sYCARCAJ50G6b4RHJokacO/Aq4AQQBeXaI+bx41hUA1YGbsqLMda7TUmI57Lg==\"}";
	char *result;
	CURLcode crv;
	size_t result_size;
	const char *encoded_result;
	unsigned char *decoded_result;
	size_t decoded_len;
	json_object *result_obj, *tmpobj;
	json_bool jsonret;
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
	apr_table_set(headers, "Content-Type", "application/x-amz-json-1.1");
	apr_table_set(headers, "X-Amz-Target", "TrentService.Decrypt");

	crv = execute_signed_aws_request(
			&result,
			&result_size,
			"POST",
			"kms",
			NULL,
			NULL,
			"/",
			queryparams,
			headers,
			payload,
			strlen(payload)
			);

	if(crv != CURLE_OK)
	{
		fprintf(stderr, "Error executing request: %s\n", result);
		return 1;
	}
	
	result_obj = json_tokener_parse(result);
	jsonret = json_object_object_get_ex(result_obj, "Plaintext", &tmpobj);
	if(!jsonret)
	{
		fprintf(stderr, "Could not retrieve plaintext.\n");
		return 1;
	}

	encoded_result = json_object_get_string(tmpobj);
	decoded_len = apr_base64_decode_len(encoded_result);
	decoded_result = malloc(decoded_len + 1);
	memset(decoded_result, 0, decoded_len + 1);
	apr_base64_decode_binary(decoded_result, encoded_result);

	fprintf(stderr, "Result: [");
	fwrite(decoded_result, 1, decoded_len, stderr);
	fprintf(stderr, "]\n");

	free(decoded_result);
	json_object_put(tmpobj);
	json_object_put(result_obj);

	apr_terminate();

	return 0;
}

