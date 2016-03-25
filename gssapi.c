/*
  This is free and unencumbered software released into the public domain.

  Anyone is free to copy, modify, publish, use, compile, sell, or
  distribute this software, either in source code form or as a compiled
  binary, for any purpose, commercial or non-commercial, and by any
  means.

  In jurisdictions that recognize copyright laws, the author or authors
  of this software dedicate any and all copyright interest in the
  software to the public domain. We make this dedication for the benefit
  of the public at large and to the detriment of our heirs and
  successors. We intend this dedication to be an overt act of
  relinquishment in perpetuity of all present and future rights to this
  software under copyright law.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.

  For more information, please refer to <http://unlicense.org/>
*/

#include <cassandra.h>

#include <stdio.h>
#include <string.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#define GSSAPI_CLIENT_STATE_NEGOTIATION    1
#define GSSAPI_CLIENT_STATE_AUTHENTICATION 2
#define GSSAPI_CLIENT_STATE_AUTHENTICATED  3

#define GSSAPI_CLIENT_ERROR    -1
#define GSSAPI_CLIENT_CONTINUE  0
#define GSSAPI_CLIENT_COMPLETE  1

#define GSSAPI_AUTH_NONE            1
#define GSSAPI_AUTH_INTEGRITY       2
#define GSSAPI_AUTH_CONFIDENTIALITY 3

typedef struct {
  gss_ctx_id_t context;
  gss_name_t server_name;
  OM_uint32 gss_flags;
  gss_cred_id_t client_creds;
  char* username;
  char* response;
  int response_size;
  int state;
} GssApiClientState;

typedef struct {
  char* service;
  char* principal;
} GssConf;

void gssapi_client_print_error(OM_uint32 err_maj, OM_uint32 err_min)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    char buf_maj[512];
    char buf_min[512];

    do
    {
      maj_stat = gss_display_status(&min_stat,
                                    err_maj,
                                    GSS_C_GSS_CODE,
                                    GSS_C_NO_OID,
                                    &msg_ctx,
                                    &status_string);
        if (GSS_ERROR(maj_stat))
            break;
        strncpy(buf_maj, (char*) status_string.value, sizeof(buf_maj));
        gss_release_buffer(&min_stat, &status_string);

        printf("%s (major %u)\n", buf_maj, err_maj);

        maj_stat = gss_display_status(&min_stat,
                                      err_min,
                                      GSS_C_MECH_CODE,
                                      GSS_C_NULL_OID,
                                      &msg_ctx,
                                      &status_string);
        if (!GSS_ERROR(maj_stat))
        {
            strncpy(buf_min, (char*) status_string.value, sizeof(buf_min));
            gss_release_buffer(&min_stat, &status_string);
        }

        printf("%s (minor %u)\n", buf_min, err_min);
    } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
}

int gssapi_client_state_init(GssApiClientState* state, const char* service, const char* principal) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;

  state->context = GSS_C_NO_CONTEXT;
  state->server_name = GSS_C_NO_NAME;
  state->gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
  state->client_creds = GSS_C_NO_CREDENTIAL;
  state->username = NULL;
  state->response = NULL;
  state->response_size = 0;
  state->state = GSSAPI_CLIENT_STATE_NEGOTIATION;

  name_token.value = (void*) service;
  name_token.length = strlen(service);
  maj_stat = gss_import_name(&min_stat, &name_token, GSS_C_NT_HOSTBASED_SERVICE, &state->server_name);

  if (GSS_ERROR(maj_stat)) {
    gssapi_client_print_error(maj_stat, min_stat);
    return GSSAPI_CLIENT_ERROR;
  }

  if (principal && *principal) {
    gss_buffer_desc principal_token = GSS_C_EMPTY_BUFFER;
    gss_name_t principal_name = GSS_C_NO_NAME;

    principal_token.value = (void*) principal;
    principal_token.length = strlen(principal);

    maj_stat = gss_import_name(&min_stat, &principal_token, GSS_C_NT_USER_NAME, &principal_name);
    if (GSS_ERROR(maj_stat)) {
      gssapi_client_print_error(maj_stat, min_stat);
      return GSSAPI_CLIENT_ERROR;
    }

    maj_stat = gss_acquire_cred(&min_stat, principal_name,
                                GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                &state->client_creds, NULL, NULL);
    if (GSS_ERROR(maj_stat)) {
      gssapi_client_print_error(maj_stat, min_stat);
      return GSSAPI_CLIENT_ERROR;
    }

    maj_stat = gss_release_name(&min_stat, &principal_name);
    if (GSS_ERROR(maj_stat)) {
      gssapi_client_print_error(maj_stat, min_stat);
      return GSSAPI_CLIENT_ERROR;
    }
  }

  return GSSAPI_CLIENT_COMPLETE;
}

void gssapi_client_state_destroy(GssApiClientState* state) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;

  if (state->context != GSS_C_NO_CONTEXT) {
    maj_stat = gss_delete_sec_context(&min_stat, &state->context, GSS_C_NO_BUFFER);
  }
  if (state->server_name != GSS_C_NO_NAME) {
    maj_stat = gss_release_name(&min_stat, &state->server_name);
  }
  if (state->client_creds != GSS_C_NO_CREDENTIAL) {
    maj_stat = gss_release_cred(&min_stat, &state->client_creds);
  }

  if (state->username) {
    free(state->username);
    state->username = NULL;
  }
  if (state->response) {
    free(state->response);
    state->response = NULL;
    state->response_size = 0;
  }
}

int gssapi_client_process(GssApiClientState* state,
                       const char* challenge, size_t challenge_length) {
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  OM_uint32 req_output_size;
  OM_uint32 max_input_size;
  unsigned char qop;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc challenge_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  int result = GSSAPI_CLIENT_COMPLETE;

  if (state->response) {
    free(state->response);
    state->response = NULL;
    state->response_size = 0;
  }

  if (challenge && challenge_length > 0) {
    challenge_token.value = (void*) challenge;
    challenge_token.length = challenge_length;
  }

  switch (state->state) {
    case GSSAPI_CLIENT_STATE_NEGOTIATION:
      maj_stat = gss_init_sec_context(&min_stat,
                                      state->client_creds,
                                      &state->context,
                                      state->server_name,
                                      GSS_C_NO_OID,
                                      state->gss_flags,
                                      0,
                                      GSS_C_NO_CHANNEL_BINDINGS,
                                      &challenge_token,
                                      NULL,
                                      &output_token,
                                      NULL,
                                      NULL);

      if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        gssapi_client_print_error(maj_stat, min_stat);
        result = GSSAPI_CLIENT_ERROR;
        goto end;
      }

      result = (maj_stat == GSS_S_COMPLETE) ? GSSAPI_CLIENT_COMPLETE
                                            : GSSAPI_CLIENT_CONTINUE;

      if (output_token.length) {
        state->response = (char *)malloc(output_token.length);
        memcpy(state->response, output_token.value, output_token.length);
        state->response_size = output_token.length;
        maj_stat = gss_release_buffer(&min_stat, &output_token);
      }

      if (result == GSSAPI_CLIENT_COMPLETE) {
        gss_name_t user_name = GSS_C_NO_NAME;

        maj_stat = gss_inquire_context(&min_stat, state->context, &user_name,
                                       NULL, NULL, NULL, NULL, NULL, NULL);

        if (GSS_ERROR(maj_stat)) {
          gssapi_client_print_error(maj_stat, min_stat);
          result = GSSAPI_CLIENT_ERROR;
          goto end;
        }

        gss_buffer_desc user_name_token = GSS_C_EMPTY_BUFFER;
        maj_stat = gss_display_name(&min_stat, user_name, &user_name_token, NULL);
        if (GSS_ERROR(maj_stat)) {
          gssapi_client_print_error(maj_stat, min_stat);
          if (user_name_token.value) {
            maj_stat = gss_release_buffer(&min_stat, &user_name_token);
          }
          maj_stat = gss_release_name(&min_stat, &user_name);
          result = GSSAPI_CLIENT_ERROR;
          goto end;
        } else {
          state->username = (char *)malloc(user_name_token.length + 1);
          strncpy(state->username, (char *)user_name_token.value, user_name_token.length);
          state->username[user_name_token.length] = '\0';
          maj_stat = gss_release_buffer(&min_stat, &user_name_token);
          maj_stat = gss_release_name(&min_stat, &user_name);
          state->state = GSSAPI_CLIENT_STATE_AUTHENTICATION;
        }
      }
      break;

    case GSSAPI_CLIENT_STATE_AUTHENTICATION:
      maj_stat = gss_unwrap(&min_stat,
                            state->context,
                            &challenge_token,
                            &output_token,
                            NULL,
                            NULL);

      if (GSS_ERROR(maj_stat)) {
        gssapi_client_print_error(maj_stat, min_stat);
        result = GSSAPI_CLIENT_ERROR;
        goto end;
      }

      if (output_token.length != 4) {
        result = GSSAPI_CLIENT_ERROR;
        goto end;
      }

      qop = ((unsigned char *) output_token.value)[0];
      if (qop & GSSAPI_AUTH_CONFIDENTIALITY) {
        qop = GSSAPI_AUTH_CONFIDENTIALITY;
      } else if (qop & GSSAPI_AUTH_INTEGRITY) {
        qop = GSSAPI_AUTH_INTEGRITY;
      } else {
        qop = GSSAPI_AUTH_NONE;
      }

      req_output_size = (((unsigned char*) output_token.value)[1] << 16) |
                        (((unsigned char*) output_token.value)[2] << 8)  |
                        (((unsigned char*) output_token.value)[3]);

      req_output_size = req_output_size & 0xFFFFFF;

      maj_stat = gss_wrap_size_limit(&min_stat, state->context,
                                     1, GSS_C_QOP_DEFAULT,
                                     req_output_size,
                                     &max_input_size);

      if (max_input_size < req_output_size) {
        req_output_size = max_input_size;
      }

      maj_stat = gss_release_buffer(&min_stat, &output_token);

      input_token.length = 4 + (state->username ? strlen(state->username) : 0);
      input_token.value = malloc(input_token.length);

      memcpy((unsigned char*) input_token.value + 4, state->username, input_token.length - 4);

      ((unsigned char*) input_token.value)[0] = qop;

      ((unsigned char*) input_token.value)[1] = (req_output_size >> 16) & 0xFF;
      ((unsigned char*) input_token.value)[2] = (req_output_size >> 8)  & 0xFF;
      ((unsigned char*) input_token.value)[3] =  req_output_size        & 0xFF;

      maj_stat = gss_wrap(&min_stat,
                          state->context,
                          0,
                          GSS_C_QOP_DEFAULT,
                          &input_token,
                          NULL,
                          &output_token);

      if (GSS_ERROR(maj_stat)) {
        gssapi_client_print_error(maj_stat, min_stat);
        result = GSSAPI_CLIENT_ERROR;
        goto end;
      }

      if (output_token.length) {
        state->response = (char *)malloc(output_token.length);
        state->response_size = output_token.length;
        memcpy(state->response, output_token.value, output_token.length);
        maj_stat = gss_release_buffer(&min_stat, &output_token);
      }

      state->state = GSSAPI_CLIENT_STATE_AUTHENTICATED;
      break;

    default:
      result = GSSAPI_CLIENT_ERROR;
      break;
  }

end:
  if (input_token.value) {
    free(input_token.value);
  }
  if (output_token.value) {
    maj_stat = gss_release_buffer(&min_stat, &output_token);
  }
  return result;
}

size_t on_auth_initial(CassAuth* auth,
                       void* data,
                       char* response,
                       size_t response_size) {
  size_t size = 0;
  char* service = NULL;

  GssConf* conf = (GssConf*) data;
  GssApiClientState* state = (GssApiClientState*) malloc(sizeof(GssApiClientState));

  size_t hostlen = strlen(auth->hostname);
  size_t servlen = strlen(conf->service);

  if (hostlen == 0)  {
    size_t len = servlen + CASS_INET_STRING_LENGTH + 1;
    char inet[CASS_INET_STRING_LENGTH];
    service = malloc(len);
    cass_inet_string(auth->host, inet);
    snprintf(service, len, "%s@%s", conf->service, inet);
  } else {
    size_t len = servlen + hostlen + 2;
    service = malloc(len);
    snprintf(service, len, "%s@%s", conf->service, auth->hostname);
  }

  if (gssapi_client_state_init(state, service, conf->principal) == GSSAPI_CLIENT_ERROR) {
    gssapi_client_state_destroy(state);
    free(state);
    goto end;
  }

  auth->exchange_data = (void*) state;

  if (gssapi_client_process(state, "", 0) == GSSAPI_CLIENT_ERROR) {
    size = CASS_AUTH_ERROR;
    goto end;
  }

  if (state->response) {
    size = state->response_size;
    if (size > response_size) {
      goto end;
    }
    memcpy(response, state->response, size);
  }

end:
  free(service);
  return size;
}

size_t on_auth_challenge(CassAuth* auth,
                         void* data,
                         const char* challenge,
                         size_t challenge_size,
                         char* response,
                         size_t response_size) {
  size_t size = 0;
  GssApiClientState* state = (GssApiClientState*) auth->exchange_data;

  if (state == NULL) return CASS_AUTH_ERROR;

  if (gssapi_client_process(state,
                            challenge, challenge_size) == GSSAPI_CLIENT_ERROR) {
    return CASS_AUTH_ERROR;
  }

  if (state->response) {
    size = state->response_size;
    if (size > response_size) {
      return size;
    }
    memcpy(response, state->response, size);
  }

  return size;
}

void on_auth_success(CassAuth* auth,
                     void* data,
                     const char* token,
                     size_t token_size ) {
  /* Not used */
}

void on_auth_cleanup(CassAuth* auth, void* data) {
  GssApiClientState* state = (GssApiClientState*) auth->exchange_data;

  if (state == NULL) return;

  gssapi_client_state_destroy(state);
  free(state);
}

int main() {
  /* Setup and connect to cluster */
  CassFuture* connect_future = NULL;
  CassCluster* cluster = cass_cluster_new();
  CassSession* session = cass_session_new();

  /* Setup authentication callbacks and credentials */
  CassAuthCallbacks auth_callbacks = {
    on_auth_initial,
    on_auth_challenge,
    on_auth_success,
    on_auth_cleanup
  };

  GssConf conf = {
    "dse",
    "cassandra@DATASTAX.COM",
  };

  cass_log_set_level(CASS_LOG_INFO);

  /* Add contact points */
  cass_cluster_set_contact_points(cluster, "127.0.0.1,127.0.0.2,127.0.0.3");

  cass_cluster_set_connect_timeout(cluster, 3000000);
  cass_cluster_set_request_timeout(cluster, 3000000);

  cass_cluster_set_use_hostname_resolution(cluster, cass_true);

  cass_cluster_set_num_threads_io(cluster, 1);
  cass_cluster_set_core_connections_per_host(cluster, 1);
  cass_cluster_set_max_connections_per_host(cluster, 1);

  /* Set custom authentication callbacks and credentials */
  cass_cluster_set_auth_callbacks(cluster, &auth_callbacks, &conf);

  /* Provide the cluster object as configuration to connect the session */
  connect_future = cass_session_connect(session, cluster);

  if (cass_future_error_code(connect_future) == CASS_OK) {
    CassFuture* close_future = NULL;

    printf("Successfully connected!\n");

    /* Close the session */
    close_future = cass_session_close(session);
    cass_future_wait(close_future);
    cass_future_free(close_future);
  } else {
    /* Handle error */
    const char* message;
    size_t message_length;
    cass_future_error_message(connect_future, &message, &message_length);
    fprintf(stderr, "Unable to connect: '%.*s'\n", (int)message_length,
                                                        message);
  }

  cass_future_free(connect_future);
  cass_cluster_free(cluster);
  cass_session_free(session);

  return 0;
}
