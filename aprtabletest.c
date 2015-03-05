#include <stdio.h>
#include <apr-1/apr_errno.h>
#include <apr-1/apr_pools.h>
#include <apr-1/apr_tables.h>
#include <apr-1/apr_strings.h>

static _get_apr_table_keys_callback(void *data, const char *key, const char *value)
{
	apr_array_header_t *arr = data;

	*(const char **)apr_array_push(arr) = apr_pstrdup(arr->pool, key);

	return 1;
}

apr_array_header_t *get_apr_table_keys(apr_pool_t *pool, apr_table_t *t)
{
	apr_array_header_t *ret = apr_array_make(pool, 16, sizeof(const char *));

	apr_table_do(_get_apr_table_keys_callback, ret, t, NULL);

	return ret;
}

static int _sort_apr_array_callback(const void *v1, const void *v2)
{
	const char *s1 = *(const char **)v1;
	const char *s2 = *(const char **)v2;

	return strcasecmp(s1, s2);
}

void sort_apr_array(apr_array_header_t *arr)
{
	qsort(arr->elts, arr->nelts, arr->elt_size, _sort_apr_array_callback);
}

int main(void)
{
	apr_status_t status;
	apr_pool_t *pool = NULL;
	apr_array_header_t *arr;
	apr_table_t *table;
	int i;
	char buf[256];

	status = apr_initialize();
	if(status != APR_SUCCESS)
	{
		fprintf(stderr, "Could not initialize APR: %s\n", apr_strerror(status, buf, sizeof(buf)));
		return -1;
	}

	status = apr_pool_create(&pool, NULL);
	if(status != APR_SUCCESS)
	{
		fprintf(stderr, "Could not create pool: %s\n", apr_strerror(status, buf, sizeof(buf)));
		return -1;
	}

	table = apr_table_make(pool, 16);

	apr_table_setn(table, "first", "one");
	apr_table_setn(table, "second", "two");
	apr_table_setn(table, "Host", "ec2.us-east-1.amazonaws.com");

	arr = get_apr_table_keys(pool, table);

	sort_apr_array(arr);

	for(i = 0; i < arr->nelts; i++)
	{
		printf("%s\n", ((const char **)arr->elts)[i]);
	}

	apr_pool_destroy(pool);

	apr_terminate();

	return 0;
}
