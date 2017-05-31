#include <arpa/inet.h>
#include <errno.h>
#include <gssapi.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int send_token_to_peer(gss_buffer_desc *token, int peer) {
	ssize_t rw_length;

	rw_length = write(peer, token->value, token->length);
	if (rw_length < 0) {
		printf("Error: writing to socket (%d:%s).\n", errno, strerror(errno));
		return 1;
	}

	return 0;
}

int receive_token_from_peer(gss_buffer_desc *token, int peer) {
	ssize_t rw_length;

	token->length = 0;
	token->value = malloc(sizeof(void) * 1024 * 32);
	rw_length = read(peer, token->value, 1024 * 32);
	if (rw_length < 0) {
		printf("Error: reading from socket (%d:%s).\n", errno, strerror(errno));
		return 1;
	}
	printf("Read: %d\n", rw_length);
	token->length = rw_length;

	return 0;
}

void print_error(OM_uint32 major, OM_uint32 minor) {
	OM_uint32 message_context;
	OM_uint32 status_code;
	OM_uint32 maj_status;
	OM_uint32 min_status;
	gss_buffer_desc status_string;

	message_context = 0;
	do {
		maj_status = gss_display_status(&min_status, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &message_context, &status_string);
		fprintf(stderr, "Major: %.*s\n", (int)status_string.length, (char *)status_string.value);
		gss_release_buffer(&min_status, &status_string);
	} while (message_context != 0);

	message_context = 0;
	do {
		maj_status = gss_display_status(&min_status, minor, GSS_C_MECH_CODE, GSS_C_NO_OID, &message_context, &status_string);
		fprintf(stderr, "Minor: %.*s\n", (int)status_string.length, (char *)status_string.value);
		gss_release_buffer(&min_status, &status_string);
	} while (message_context != 0);
}

int main() {
	int enable = 1;
	int client_socket;
	ssize_t rw_length;
	struct sockaddr_in srv_addr;
	char *data = malloc(sizeof(char) * 1024 * 32);

	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket == -1) {
		printf("Error: socket connection error.\n");
		return 1;
	}
	setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(2025);
	if (inet_aton("192.168.122.49", &srv_addr.sin_addr) == 0) {
		// if (inet_aton("127.0.0.1", &srv_addr.sin_addr) == 0) {
		printf("Error: invalid address.\n");
		return 2;
	}

	if (connect(client_socket, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1) {
		printf("Error: binding to socket (%d:%s).\n", errno, strerror(errno));
		return 3;
	}

	rw_length = write(client_socket, "auth\0", 5);
	if (rw_length < 0) {
		printf("Error: writing to socket (%d:%s).\n", errno, strerror(errno));
		return 4;
	}

	printf("Sent auth...\n");

	rw_length = read(client_socket, data, 1024 * 32);
	if (strncmp(data, "ack", 3) != 0) {
		printf("Error: reading from socket (%d:%s).\n", errno, strerror(errno));
		return 5;
	}

	printf("Received ack...\n");
	printf("Beginning GSSAPI transmissions.\n");

	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	gss_cred_id_t creds;
	gss_OID_set mechs;
	OM_uint32 time_rec;

	maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET, GSS_C_INITIATE, &creds, &mechs, &time_rec);
	if (GSS_ERROR(maj_stat)) {
		printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
		print_error(maj_stat, min_stat);
		return 6;
	}

	gss_name_t cred_name;
	maj_stat = gss_inquire_cred(&min_stat, creds, &cred_name, NULL, NULL, NULL);
	if (GSS_ERROR(maj_stat)) {
		printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
		print_error(maj_stat, min_stat);
		return 6;
	}

	gss_buffer_desc exported_name;
	maj_stat = gss_display_name(&min_stat, cred_name, &exported_name, NULL);
	if (GSS_ERROR(maj_stat)) {
		printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
		print_error(maj_stat, min_stat);
		return 6;
	}

	printf("Name (%d): %s\n", exported_name.length, exported_name.value);

	int context_established = 0;
	gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
	gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

	OM_uint32 flags_rec;

	// receive_token_from_peer(&input_token, client_socket);

	gss_buffer_desc server_canonical_name;
	gss_name_t server_name;
	server_canonical_name.value = "TEST/kdc.cipherboy.com@CIPHERBOY.COM";
	server_canonical_name.length = 36;

	maj_stat = gss_import_name(&min_stat, &server_canonical_name, GSS_C_NO_OID, &server_name);
	if (GSS_CALLING_ERROR(maj_stat)) {
		printf("GSS (name)_ERROR: %u:%u\n", maj_stat, min_stat);
		print_error(maj_stat, min_stat);
		return 5;
	}

	while (!context_established) {
		maj_stat = gss_init_sec_context(&min_stat, creds, &ctx_handle, server_name, GSS_C_NO_OID, 0, 0, GSS_C_NO_CHANNEL_BINDINGS, &input_token, NULL, &output_token, &flags_rec, &time_rec);
		if (GSS_CALLING_ERROR(maj_stat)) {
			printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
			print_error(maj_stat, min_stat);
			return 6;
		}

		if (output_token.length != 0) {
			printf("Have to send token (%d) to peer.\n", output_token.length);
			if (send_token_to_peer(&output_token, client_socket) != 0) {
				return 7;
			}
		}

		if (maj_stat & GSS_S_CONTINUE_NEEDED) {
			receive_token_from_peer(&input_token, client_socket);
			printf("Received token (%d) from peer.\n", input_token.length);
		} else {
			context_established = 1;
		}
	}

	if (!context_established) {
		return 8;
	}
	printf("Context established on client!\n");

	close(client_socket);
}
