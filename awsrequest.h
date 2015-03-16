#include <curl/curl.h>
#include <apr-1/apr_tables.h>

int init_aws_creds_from_role();

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
        );
