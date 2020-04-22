#include <arpa/inet.h>
#include <microhttpd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

#define PAGE "401 Unauthorized\n\n"

static int ahc_echo(void * cls,
		    struct MHD_Connection * connection,
		    const char * url,
		    const char * method,
                    const char * version,
		    const char * upload_data,
		    size_t * upload_data_size,
                    void ** ptr) {
	static int dummy;
	int ret;
	const char * page = cls;
	const char * user_agent;
	char * username;
	char ** password;
	struct MHD_Response * response;
	struct sockaddr_in * so;


  	if (0 != strcmp(method, "GET") || 0 != strcmp(method, "HEAD")) return MHD_NO;
	if (&dummy != *ptr) {
		*ptr = &dummy;
		return MHD_YES;
  	}
  	if (0 != *upload_data_size) return MHD_NO;

  	*ptr = NULL;

	so = (struct sockaddr_in *)MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
	char * client_ip = inet_ntoa(so->sin_addr);

	user_agent = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "User-Agent");

	response = MHD_create_response_from_buffer (strlen(page), (void*) page, MHD_RESPMEM_PERSISTENT);

  	ret = MHD_queue_basic_auth_fail_response(connection, "Restricted Content", response);
	username = MHD_basic_auth_get_username_password(connection, password);

	time_t now;
	time(&now);

	FILE * fp = fopen("auth.log", "a");
	if (username != NULL && password != NULL) 
		fprintf(fp, "[%.*s] %s \"%s\" %s:%s\n", 24, ctime(&now), client_ip, user_agent, username, *password);
	fclose(fp);

  	MHD_destroy_response(response);

  	return ret;
}

static long get_file_size(const char * filename) {
	FILE * fp;

	fp = fopen(filename, "rb");
	if (fp) {
		long size;

		if ((0 != fseek(fp, 0, SEEK_END)) || (-1 == (size = ftell(fp)))) size = 0;

		fclose(fp);
		return size;
	} else return 0;
}

static char * load_file(const char * filename) {
	FILE * fp;
	char * buffer;
	long size;

	size = get_file_size(filename);	
	if (0 == size) return NULL;

	fp = fopen(filename, "rb");
	if (!fp) return NULL;

	buffer = malloc(size + 1);
	if (!buffer) {
		fclose(fp);
		return NULL;
	}
	buffer[size] = '\0';

	if (size != (long)fread(buffer, 1, size, fp)) {
		free(buffer);
		buffer = NULL;
	}

	fclose(fp);
	return buffer;
}

int main(int argc, char ** argv) {
	struct MHD_Daemon * d;
	char * key_pem;
	char * cert_pem;

	if (argc != 4) {
		printf("%s <port> <key_pem> <cert_pem>\n", argv[0]);
		return 1;
	}

	key_pem = load_file(argv[2]);
	cert_pem = load_file(argv[3]);

	d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL,
			atoi(argv[1]), NULL, NULL,
			&ahc_echo, PAGE,
			MHD_OPTION_HTTPS_MEM_KEY, key_pem,
			MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
			MHD_OPTION_END);

	if (d == NULL) return 1;

	(void)getc(stdin);
	MHD_stop_daemon(d);

	return 0;
}
