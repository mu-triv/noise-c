/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <noise/protocol.h>
#include "echo-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define short_options "c:s:p:gvf"

static struct option const long_options[] = {
    {"client-private-key",      required_argument,      NULL,       'c'},
    {"server-public-key",       required_argument,      NULL,       's'},
    {"psk",                     required_argument,      NULL,       'p'},
    {"padding",                 no_argument,            NULL,       'g'},
    {"verbose",                 no_argument,            NULL,       'v'},
    {"fixed-ephemeral",         no_argument,            NULL,       'f'},
    {NULL,                      0,                      NULL,        0 }
};

/* Parsed command-line options */
static uint8_t psk[32];
static const char *protocol = "Noise_KK_25519_AESGCM_SHA256";
static const char *hostname = NULL;
static int port = 7000;
static int padding = 0;
static int fixed_ephemeral = 0;

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 4096
static uint8_t message[MAX_MESSAGE_LEN + 2];

/* Curve25519 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_25519[32] = {
    0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6,
    0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7,
    0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a,
    0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a
};

/* Curve448 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_448[56] = {
    0x7f, 0xd2, 0x6c, 0x8b, 0x8a, 0x0d, 0x5c, 0x98,
    0xc8, 0x5f, 0xf9, 0xca, 0x1d, 0x7b, 0xc6, 0x6d,
    0x78, 0x57, 0x8b, 0x9f, 0x2c, 0x4c, 0x17, 0x08,
    0x50, 0x74, 0x8b, 0x27, 0x99, 0x27, 0x67, 0xe6,
    0xea, 0x6c, 0xc9, 0x99, 0x2a, 0x56, 0x1c, 0x9d,
    0x19, 0xdf, 0xc3, 0x42, 0xe2, 0x60, 0xc2, 0x80,
    0xef, 0x4f, 0x3f, 0x9b, 0x8f, 0x87, 0x9d, 0x4e
};

/* New Hope private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_newhope[64] = {
    0x93, 0x4d, 0x60, 0xb3, 0x56, 0x24, 0xd7, 0x40,
    0xb3, 0x0a, 0x7f, 0x22, 0x7a, 0xf2, 0xae, 0x7c,
    0x67, 0x8e, 0x4e, 0x04, 0xe1, 0x3c, 0x5f, 0x50,
    0x9e, 0xad, 0xe2, 0xb7, 0x9a, 0xea, 0x77, 0xe2,
    0x3e, 0x2a, 0x2e, 0xa6, 0xc9, 0xc4, 0x76, 0xfc,
    0x49, 0x37, 0xb0, 0x13, 0xc9, 0x93, 0xa7, 0x93,
    0xd6, 0xc0, 0xab, 0x99, 0x60, 0x69, 0x5b, 0xa8,
    0x38, 0xf6, 0x49, 0xda, 0x53, 0x9c, 0xa3, 0xd0
};

/* Print usage information */
static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options] hostname port\n\n", progname);
    fprintf(stderr, "Options:\n\n");
    fprintf(stderr, "    --padding, -g\n");
    fprintf(stderr, "        Pad messages with random data to a uniform size.\n\n");
    fprintf(stderr, "    --verbose, -v\n");
    fprintf(stderr, "        Print all messages to and from the echo server.\n\n");
}

/* Parse the command-line options */
static int parse_options(int argc, char *argv[])
{
    const char *progname = argv[0];
    int index = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (ch) {
        case 'g':   padding = 1; break;
        case 'v':   echo_verbose = 1; break;
        default:
            usage(progname);
            return 0;
        }
    }
    if ((optind + 2) != argc) {
        usage(progname);
        return 0;
    }
    hostname = argv[optind + 0];
    port = atoi(argv[optind + 1]);
    if (port < 1 || port > 65535) {
        usage(progname);
        return 0;
    }
    return 1;
}

/* Set a fixed ephemeral key for testing */
static int set_fixed_ephemeral(NoiseDHState *dh)
{
    if (!dh)
        return NOISE_ERROR_NONE;
    if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
        return noise_dhstate_set_keypair_private
            (dh, fixed_ephemeral_25519, sizeof(fixed_ephemeral_25519));
    } else if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE448) {
        return noise_dhstate_set_keypair_private
            (dh, fixed_ephemeral_448, sizeof(fixed_ephemeral_448));
    } else if (noise_dhstate_get_dh_id(dh) == NOISE_DH_NEWHOPE) {
        return noise_dhstate_set_keypair_private
            (dh, fixed_ephemeral_newhope, sizeof(fixed_ephemeral_newhope));
    } else {
        return NOISE_ERROR_UNKNOWN_ID;
    }
}


static const char* app_key_packet = "{\"signature\": \"c6dbf5d7c8df34bacce82fee7e86efdb1184b8518e203847fe31dc470919d89de54d5014916c3c83aaaafd55ba0aaed73b1474ca54fcbcf81ed5451da734cd07\", \"app_hash\": \"746869732d617070\", \"app_pubkey\": \"9ba2901502d2bce725a384a7d3d33b8db7c1dd820f4b47954c88330deb491e04\", \"device_id\": \"3465623561303863626133616132333834316433313535393066656536643861\", \"attestation\": {\"user_data\": \"ea698c680d1a3fb7dad99fce281857238f437fd2ed1539a1891f735713c2684c\", \"app_hash\": \"746869732d617070\", \"signature\": \"42e7493f59a19fa59c492c0acefe74bca24976c426199d1731bb6368f7b307b3cc3f1587f52bb19339844aa409bb2381a9b32aad85c9bc41017020acb6d1530b\", \"secure_runtime\": \"5365637572652052756e74696d652076312e312e30\"}}";
static const uint8_t client_key_25519_priv[] = {0xf8, 0x95, 0x93, 0xd7, 0x25, 0x96, 0x2d, 0x85, 0xa1, 0xdd, 0x7d, 0x36, 0x31, 0x0b, 0x39, 0xa0, 0x59, 0x8d, 0x1b, 0xe4, 0x92, 0xe2, 0x7b, 0x17, 0x14, 0xaf, 0x62, 0xe0, 0xef, 0xa9, 0x99, 0x45};
static const uint8_t server_key_25519_pub[] = {0xf3, 0x1b, 0x76, 0xd3, 0x8b, 0x22, 0x94, 0xad, 0xe9, 0x9b, 0xac, 0x66, 0x11, 0x5f, 0xeb, 0x55, 0xb9, 0xa7, 0x10, 0xc9, 0x43, 0x1e, 0xf5, 0x81, 0x29, 0x6c, 0x5c, 0x42, 0x73, 0x60, 0x64, 0x26};

/* Initialize the handshake using command-line options */
static int initialize_handshake(NoiseHandshakeState *handshake)
{
    NoiseDHState *dh;
    uint8_t *key = 0;
    size_t key_len = 0;
    int err;

    /* Set the local keypair for the client */
    if (noise_handshakestate_needs_local_keypair(handshake)) {
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        err = noise_dhstate_set_keypair_private(dh, client_key_25519_priv, sizeof(client_key_25519_priv));
    }

    /* Set the remote public key for the server */
    if (noise_handshakestate_needs_remote_public_key(handshake)) {
        dh = noise_handshakestate_get_remote_public_key_dh(handshake);
        err = noise_dhstate_set_public_key(dh, server_key_25519_pub, sizeof(server_key_25519_pub));
    }

    return 1;
}

int main(int argc, char *argv[])
{
    NoiseHandshakeState *handshake;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    NoiseRandState *rand = 0;
    NoiseBuffer mbuf;
    EchoProtocolId id;
    int err, ok;
    int action;
    int fd;
    size_t message_size;
    size_t max_line_len;

    /* Parse the command-line options */
    if (!parse_options(argc, argv))
        return 1;

    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    /* Check that the echo protocol supports the handshake protocol.
       One-way handshake patterns and XXfallback are not yet supported. */
    if (!echo_get_protocol_id(&id, protocol)) {
        fprintf(stderr, "%s: not supported by the echo protocol\n", protocol);
        return 1;
    }

    /* Create a HandshakeState object for the protocol */
    err = noise_handshakestate_new_by_name
        (&handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    /* Set the handshake options and verify that everything we need
       has been supplied on the command-line. */
    if (!initialize_handshake(handshake)) {
        noise_handshakestate_free(handshake);
        return 1;
    }

    /* Attempt to connect to the remote party */
    fd = echo_connect(hostname, port);
    if (fd < 0) {
        noise_handshakestate_free(handshake);
        return 1;
    }

    message[0] = (uint8_t)(strlen(app_key_packet) >> 8);
    message[1] = (uint8_t)strlen(app_key_packet);
    memcpy(message + 2, app_key_packet, strlen(app_key_packet));
    printf("strlen(app_key_packet): %d\n", strlen(app_key_packet));

    /* Send the echo protocol identifier to the server */
    ok = 1;
    if (!echo_send(fd, message, strlen(app_key_packet) + 2))
        ok = 0;

    /* Start the handshake */
    if (ok) {
        err = noise_handshakestate_start(handshake);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }

    /* Run the handshake until we run out of things to read or write */
    while (ok) {
        action = noise_handshakestate_get_action(handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }
            message[0] = (uint8_t)(mbuf.size >> 8);
            message[1] = (uint8_t)mbuf.size;
            if (!echo_send(fd, message, mbuf.size + 2)) {
                ok = 0;
                break;
            }
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            /* Read the next handshake message and discard the payload */
            message_size = echo_recv(fd, message, sizeof(message));
            if (!message_size) {
                ok = 0;
                break;
            }
            noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("read handshake", err);
                ok = 0;
                break;
            }
        } else {
            /* Either the handshake has finished or it has failed */
            break;
        }
    }

    /* If the action is not "split", then the handshake has failed */
    if (ok && noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "protocol handshake failed\n");
        ok = 0;
    }

    /* Split out the two CipherState objects for send and receive */
    if (ok) {
        err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("split to start data transfer", err);
            ok = 0;
        }
    }

    size_t hash_max_len = noise_hashstate_get_max_hash_length();
    uint8_t *handshake_hash = (uint8_t *)malloc(hash_max_len);
    err = noise_handshakestate_get_handshake_hash(handshake, handshake_hash, hash_max_len);
    if (NOISE_ERROR_NONE != err)
    {
        noise_perror("noise_handshakestate_get_handshake_hash() failed", err);
        ok = 0;
    }

    /* We no longer need the HandshakeState */
    noise_handshakestate_free(handshake);
    handshake = 0;

    /* Clean up and exit */
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);
    noise_randstate_free(rand);
    echo_close(fd);
    return ok ? 0 : 1;
}

#include "echo-common.c"
