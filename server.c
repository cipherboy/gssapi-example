#include <arpa/inet.h>
#include <errno.h>
#include <gssapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ERROR_MAJOR 1
#define ERROR_MINOR 2

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
	int srv_socket;
	int client_socket;
	ssize_t rw_length;
	struct sockaddr_in srv_addr;
	char *data = malloc(sizeof(char) * 1024 * 32);

	srv_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_socket == -1) {
		printf("Error: socket connection error.\n");
		return 1;
	}
	if (setsockopt(srv_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		printf("Error: setting socket options failed.\n");
		return 2;
	}

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(2025);
	srv_addr.sin_addr.s_addr = htons(INADDR_ANY);

	if (bind(srv_socket, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1) {
		printf("Error: binding to socket (%d:%s).\n", errno, strerror(errno));
		return 3;
	}

	if (listen(srv_socket, 10) == -1) {
		printf("Error: listening to socket (%d:%s).\n", errno, strerror(errno));
		return 4;
	}

	printf("Successfully listening on 2025...\n");

	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	gss_cred_id_t server_creds;
	gss_OID_set server_mechs;

	maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &server_creds, &server_mechs, NULL);
	if (GSS_ERROR(maj_stat)) {
		printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
		print_error(maj_stat, min_stat);
		return 4;
	}

	while (1) {
		client_socket = accept(srv_socket, (struct sockaddr *)NULL, NULL);
		if (client_socket == -1) {
			printf("Error: accepting socket error (%d:%s).", errno, strerror(errno));
			return 5;
		}
		printf("Successfully accepted client:\n");

		rw_length = read(client_socket, data, 1024 * 32);
		if (strncmp(data, "auth", 4) != 0) {
			printf("Didn't send auth...\n");
			continue;
		}

		printf("Got auth.\n");

		rw_length = write(client_socket, "ack\n", 4);
		if (rw_length != 4) {
			printf("Error: Unable to write all data to socket.\n");
			break;
		}

		printf("Wrote ack.\n");
		printf("Beginning GSSAPI transmissions.\n");

		gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;

		gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
		gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
		gss_cred_id_t client_cred = GSS_C_NO_CREDENTIAL;
		gss_name_t client_name;
		gss_OID mech_OID;

		int context_established = 0;

		while (!context_established) {
			maj_stat = gss_accept_sec_context(&min_stat, &ctx_handle, server_creds, &input_token, GSS_C_NO_CHANNEL_BINDINGS, &client_name, &mech_OID, &output_token, NULL, NULL, &client_cred);
			if (GSS_ERROR(maj_stat)) {
				printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
				print_error(maj_stat, min_stat);
				return 6;
			}

			if (output_token.length != 0) {
				printf("Have to send token (%d) to peer.\n", output_token.length);
				if (send_token_to_peer(&output_token, client_socket) != 0) {
					return 7;
				}
				output_token.length = 0;
			}

			if (maj_stat & GSS_S_CONTINUE_NEEDED) {
				printf("Have to wait for token...\n");
				receive_token_from_peer(&input_token, client_socket);
				printf("Received token (%d) from peer.\n", input_token.length);
			} else {
				context_established = 1;
			}
		}

		if (ctx_handle == GSS_C_NO_CONTEXT) {
			printf("Still no context... but done?\n");
		}

		if (!context_established) {
			return 8;
		}
		printf("Context established on server!\n");

		gss_name_t src_name;
		gss_name_t target_name;
		maj_stat = gss_inquire_context(&min_stat, ctx_handle, &src_name, &target_name, NULL, NULL, NULL, NULL, NULL);
		if (GSS_ERROR(maj_stat)) {
			printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
			print_error(maj_stat, min_stat);
			return 9;
		}

		gss_buffer_desc exported_name;
		maj_stat = gss_display_name(&min_stat, src_name, &exported_name, NULL);
		if (GSS_ERROR(maj_stat)) {
			printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
			print_error(maj_stat, min_stat);
			return 10;
		}

		printf("Source Name (%d): %s\n", exported_name.length, exported_name.value);

		maj_stat = gss_display_name(&min_stat, target_name, &exported_name, NULL);
		if (GSS_ERROR(maj_stat)) {
			printf("GSS_ERROR: %u:%u\n", maj_stat, min_stat);
			print_error(maj_stat, min_stat);
			return 10;
		}

		printf("Target Name (%d): %s\n", exported_name.length, exported_name.value);
	}

	close(srv_socket);

	return 0;
}
