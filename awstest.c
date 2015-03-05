#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json/json.h>

struct memstruct
{
	char *mem;
	size_t size;
};

static size_t curl_writemem_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct memstruct *mem = (struct memstruct *)userp;

	mem->mem = realloc(mem->mem, mem->size + realsize + 1);

	if(mem->mem == NULL)
	{
		fprintf(stderr, "could not allocate memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->mem[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->mem[mem->size] = 0;

	return realsize;
}

int main(void)
{
	char credpath[128] = "http://169.254.169.254/2014-11-05/meta-data/iam/security-credentials/";
	json_object *credobj, *tmpobj;
	json_bool jsonret;
	const char *accesskeyid, *secretaccesskey, *token;
	CURL *ch;
	CURLcode res;

	struct memstruct tmp;

	tmp.mem = malloc(1);
	tmp.size = 0;

	ch = curl_easy_init();

	if(!ch)
	{
		fprintf(stderr, "Could not initialize curl.\n");
		return 1;
	}

	curl_easy_setopt(ch, CURLOPT_URL, credpath);
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_writemem_callback);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)&tmp);

	res = curl_easy_perform(ch);

	if(res != CURLE_OK)
	{
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	} else {
		printf("got response body:\n%s\n", tmp.mem);
	}

	curl_easy_cleanup(ch);

	strncat(credpath, tmp.mem, sizeof(credpath));

	printf("new credpath: %s\n", credpath);

	free(tmp.mem);
	tmp.mem = malloc(1);
	tmp.size = 0;

	ch = curl_easy_init();
	if(!ch)
	{
		fprintf(stderr, "Could not initialize curl.\n");
		return 1;
	}

	curl_easy_setopt(ch, CURLOPT_URL, credpath);
	curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_writemem_callback);
	curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)&tmp);

	res = curl_easy_perform(ch);

	if(res != CURLE_OK)
	{
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	} else {
		printf("got response body: %s\n", tmp.mem);
	}

	curl_easy_cleanup(ch);

	credobj = json_tokener_parse(tmp.mem);

	jsonret = json_object_object_get_ex(credobj, "AccessKeyId", &tmpobj);
	if(!jsonret)
	{
		fprintf(stderr, "could not get AccessKeyId\n");
		return 1;
	}
	accesskeyid = json_object_get_string(tmpobj);

	printf("got AccessKeyId: %s\n", accesskeyid);

	jsonret = json_object_object_get_ex(credobj, "SecretAccessKey", &tmpobj);
	if(!jsonret)
	{
		fprintf(stderr, "could not get SecretAccessKey\n");
		return 1;
	}
	secretaccesskey = json_object_get_string(tmpobj);

	printf("got SecretAccessKey: %s\n", secretaccesskey);

	jsonret = json_object_object_get_ex(credobj, "Token", &tmpobj);
	if(!jsonret)
	{
		fprintf(stderr, "could not get Token\n");
		return 1;
	}
	token = json_object_get_string(tmpobj);

	printf("got Token: %s\n", token);

	return 0;
}
