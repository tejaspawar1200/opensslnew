/*
 *  Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

/*
 * NB: Changes to this file should also be reflected in
 * doc/man7/ossl-guide-quic-server-non-block.pod
 */

#include <string.h>

/* Include the appropriate header file for SOCK_STREAM */
#ifdef _WIN32 /* Windows */
# include <stdarg.h>
# include <winsock2.h>
#else /* Linux/Unix */
# include <err.h>
# include <sys/socket.h>
# include <sys/select.h>
# include <netinet/in.h>
# include <unistd.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

#ifdef _WIN32
static const char *progname;

static void vwarnx(const char *fmt, va_list ap)
{
    if (progname != NULL)
        fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    putc('\n', stderr);
}

static void errx(int status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
    exit(status);
}

static void warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}
#endif

/*
 * ALPN strings for TLS handshake. Only 'http/1.0' and 'hq-interop'
 * are accepted.
 */
static const unsigned char alpn_ossltest[] = {
    8,  'h', 't', 't', 'p', '/', '1', '.', '0',
    10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p',
};

/*
 * This callback validates and negotiates the desired ALPN on the server side.
 */
static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    /*
     * An SSL_CTX holds shared configuration information for multiple
     * subsequent per-client connections. We specifically load a QUIC
     * server method here.
     */
    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /*
     * Load the server's certificate *chain* file (PEM format), which includes
     * not only the leaf (end-entity) server certificate, but also any
     * intermediate issuer-CA certificates.  The leaf certificate must be the
     * first certificate in the file.
     *
     * In advanced use-cases this can be called multiple times, once per public
     * key algorithm for which the server has a corresponding certificate.
     * However, the corresponding private key (see below) must be loaded first,
     * *before* moving on to the next chain file.
     *
     * The requisite files "chain.pem" and "pkey.pem" can be generated by running
     * "make chain" in this directory.  If the server will be executed from some
     * other directory, move or copy the files there.
     */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    /*
     * Load the corresponding private key, this also checks that the private
     * key matches the just loaded end-entity certificate.  It does not check
     * whether the certificate chain is valid, the certificates could be
     * expired, or may otherwise fail to form a chain that a client can validate.
     */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    /*
     * Clients rarely employ certificate-based authentication, and so we don't
     * require "mutual" TLS authentication (indeed there's no way to know
     * whether or how the client authenticated the server, so the term "mutual"
     * is potentially misleading).
     *
     * Since we're not soliciting or processing client certificates, we don't
     * need to configure a trusted-certificate store, so no call to
     * SSL_CTX_set_default_verify_paths() is needed.  The server's own
     * certificate chain is assumed valid.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Setup ALPN negotiation callback to decide which ALPN is accepted. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket on the given port. */
static int create_socket(uint16_t port)
{
    int fd;
    struct sockaddr_in sa = {0};

    /* Retrieve the file descriptor for a new UDP socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "cannot create socket");
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    /* Bind to the new UDP socket on localhost */
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "cannot bind to %u\n", port);
        BIO_closesocket(fd);
        return -1;
    }

    /* Set port to nonblocking mode */
    if (BIO_socket_nbio(fd, 1) <= 0) {
        fprintf(stderr, "Unable to set port to nonblocking mode");
        BIO_closesocket(fd);
        return -1;
    }

    return fd;
}

/**
 * @brief Waits for activity on the SSL socket, either for reading or writing.
 *
 * This function monitors the underlying file descriptor of the given SSL
 * connection to determine when it is ready for reading or writing, or both.
 * It uses the select function to wait until the socket is either readable
 * or writable, depending on what the SSL connection requires.
 *
 * @param ssl A pointer to the SSL object representing the connection.
 *
 * @note This function blocks until there is activity on the socket. In a real
 * application, you might want to perform other tasks while waiting, such as
 * updating a GUI or handling other connections.
 *
 * @note This function uses select for simplicity and portability. Depending
 * on your application's requirements, you might consider using other
 * mechanisms like poll or epoll for handling multiple file descriptors.
 */
static void wait_for_activity(SSL *ssl)
{
    int sock, isinfinite;
    fd_set read_fd, write_fd;
    struct timeval tv;
    struct timeval *tvp = NULL;

    /* Get hold of the underlying file descriptor for the socket */
    if ((sock = SSL_get_fd(ssl)) == -1) {
        fprintf(stderr, "Unable to get file descriptor");
        return;
    }

    /* Initialize the fd_set structure */
    FD_ZERO(&read_fd);
    FD_ZERO(&write_fd);

    /*
     * Determine if we would like to write to the socket, read from it, or both.
     */
    if (SSL_net_write_desired(ssl))
        FD_SET(sock, &write_fd);
    if (SSL_net_read_desired(ssl))
        FD_SET(sock, &read_fd);

    /* Add the socket file descriptor to the fd_set */
    FD_SET(sock, &read_fd);
    FD_SET(sock, &write_fd);

    /*
     * Find out when OpenSSL would next like to be called, regardless of
     * whether the state of the underlying socket has changed or not.
     */
    if (SSL_get_event_timeout(ssl, &tv, &isinfinite) && !isinfinite)
        tvp = &tv;

    /*
     * Wait until the socket is writeable or readable. We use select here
     * for the sake of simplicity and portability, but you could equally use
     * poll/epoll or similar functions
     *
     * NOTE: For the purposes of this demonstration code this effectively
     * makes this demo block until it has something more useful to do. In a
     * real application you probably want to go and do other work here (e.g.
     * update a GUI, or service other connections).
     *
     * Let's say for example that you want to update the progress counter on
     * a GUI every 100ms. One way to do that would be to use the timeout in
     * the last parameter to "select" below. If the tvp value is greater
     * than 100ms then use 100ms instead. Then, when select returns, you
     * check if it did so because of activity on the file descriptors or
     * because of the timeout. If the 100ms GUI timeout has expired but the
     * tvp timeout has not then go and update the GUI and then restart the
     * "select" (with updated timeouts).
     */

    select(sock + 1, &read_fd, &write_fd, NULL, tvp);
}

/**
 * @brief Handles I/O failures on an SSL connection based on the result code.
 *
 * This function processes the result of an SSL I/O operation and handles
 * different types of errors that may occur during the operation. It takes
 * appropriate actions such as retrying the operation, reporting errors, or
 * returning specific status codes based on the error type.
 *
 * @param ssl A pointer to the SSL object representing the connection.
 * @param res The result code from the SSL I/O operation.
 * @return An integer indicating the outcome:
 *         - 1: Temporary failure, the operation should be retried.
 *         - 0: EOF, indicating the connection has been closed.
 *         - -1: A fatal error occurred or the connection has been reset.
 *
 * @note This function may block if a temporary failure occurs and
 * wait_for_activity() is called.
 *
 * @note If the failure is due to an SSL verification error, additional
 * information will be logged to stderr.
 */
static int handle_io_failure(SSL *ssl, int res)
{
    switch (SSL_get_error(ssl, res)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        /* Temporary failure. Wait until we can read/write and try again */
        wait_for_activity(ssl);
        return 1;

    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_NONE:
        /* EOF */
        return 0;

    case SSL_ERROR_SYSCALL:
        return -1;

    case SSL_ERROR_SSL:
        /*
         * Some stream fatal error occurred. This could be because of a
         * stream reset - or some failure occurred on the underlying
         * connection.
         */
        switch (SSL_get_stream_read_state(ssl)) {
        case SSL_STREAM_STATE_RESET_REMOTE:
            printf("Stream reset occurred\n");
            /*
             * The stream has been reset but the connection is still
             * healthy.
             */
            break;

        case SSL_STREAM_STATE_CONN_CLOSED:
            printf("Connection closed\n");
            /* Connection is already closed. */
            break;

        default:
            printf("Unknown stream failure\n");
            break;
        }
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            printf("Verify error: %s\n",
                   X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        return -1;

    default:
        return -1;
    }
}

/*
 * Main loop for server to accept QUIC connections.
 * Echo every request back to the client.
 */
static int run_quic_server(SSL_CTX *ctx, int fd)
{
    int ok = -1;
    int ret, eof;
    SSL *listener, *conn = NULL;
    unsigned char buf[8192];
    size_t nread, nwritten, total_read, total_written;

    /* Create a new QUIC listener */
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    /* Provide the listener with our UDP socket. */
    if (!SSL_set_fd(listener, fd))
        goto err;

    /*
     * Set the listener mode to non-blocking, which is inherited by
     * child objects.
     */
    if (!SSL_set_blocking_mode(listener, 0))
        goto err;

    /* Begin listening. */
    if (!SSL_listen(listener))
        goto err;

    /*
     * Begin an infinite loop of listening for connections. We will only
     * exit this loop if we encounter an error.
     */
    for (;;) {
        eof = 0;
        total_read = 0;
        total_written = 0;

        /* Pristine error stack for each new connection */
        ERR_clear_error();

        /* Block while waiting for a client connection */
        printf("Waiting for connection\n");
        while ((conn = SSL_accept_connection(listener, 0)) == NULL)
            wait_for_activity(listener);
        printf("Accepted new connection\n");

        /* Read from client until the client sends a end of stream packet */
        while (!eof) {
            ret = SSL_read_ex(conn, buf + total_read, sizeof(buf) - total_read,
                              &nread);
            total_read += nread;
            if (total_read >= 8192) {
                fprintf(stderr, "Could not fit all data into buffer\n");
                goto err;
            }

            switch (handle_io_failure(conn, ret)) {
            case 1:
                continue; /* Retry */
            case 0:
                /* Reached end of stream */
                if (!SSL_has_pending(conn))
                    eof = 1;
                break;
            default:
                fprintf(stderr, "Failed reading remaining data\n");
                goto err;
            }
        }

        /* Echo client input */
        while (!SSL_write_ex2(conn, buf + total_written,
                              total_read - total_written,
                              SSL_WRITE_FLAG_CONCLUDE, &nwritten)) {
            total_written += nwritten;
            if (handle_io_failure(conn, 0) == 1)
                continue;
            fprintf(stderr, "Failed to write data\n");
            goto err;
        }
        total_written += nwritten;

        if (total_read != total_written)
            fprintf(stderr, "Failed to echo data [read: %lu, written: %lu]\n",
                    total_read, total_written);

        /*
         * Shut down the connection. We may need to call this multiple times
         * to ensure the connection is shutdown completely.
         */
        while (SSL_shutdown(conn) != 1)
            continue;

        SSL_free(conn);
    }

    ok = EXIT_SUCCESS;
err:
    SSL_free(listener);
    return ok;
}

/* Minimal QUIC HTTP/1.0 server. */
int main(int argc, char *argv[])
{
    int res = EXIT_FAILURE;
    SSL_CTX *ctx = NULL;
    int fd;
    unsigned long port;

#ifdef _WIN32
    progname = argv[0];
#endif

    if (argc != 4)
        errx(res, "usage: %s <port> <server.crt> <server.key>", argv[0]);

    /* Create SSL_CTX that supports QUIC. */
    if ((ctx = create_ctx(argv[2], argv[3])) == NULL) {
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create context");
    }

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        SSL_CTX_free(ctx);
        errx(res, "Failed to parse port number");
    }

    /* Create and bind a UDP socket. */
    if ((fd = create_socket((uint16_t)port)) < 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create socket");
    }

    /* QUIC server connection acceptance loop. */
    if (run_quic_server(ctx, fd) < 0) {
        SSL_CTX_free(ctx);
        BIO_closesocket(fd);
        ERR_print_errors_fp(stderr);
        errx(res, "Error in QUIC server loop");
    }

    /* Free resources. */
    SSL_CTX_free(ctx);
    BIO_closesocket(fd);
    res = EXIT_SUCCESS;
    return res;
}
