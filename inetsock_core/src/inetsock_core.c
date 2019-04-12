///////////////////////////////////////////////////////////////////////////////
// inetsock_core.c: Implementations for the functions in this shared library

#include "stdafx.h"
#include "inetsock_core.h"

#define CONNECT_OPERATION_FAILED "connect: Failed to contact server on '%s' and port %d.\n"

pthread_mutex_t* g_pSocketMutex; /* mutex for socket access */

///////////////////////////////////////////////////////////////////////////////
// CreateSocketMutex function - Allocates operating system resources for the
// socket mutex handle.
//

void CreateSocketMutex() {
    // If the socket mutex is already not NULL, assume it's
    // already been created; therefore, we have nothing to do here.
    if (NULL != g_pSocketMutex) {
        return;
    }

    g_pSocketMutex = (pthread_mutex_t*) malloc(1 * sizeof(pthread_mutex_t));
    if (g_pSocketMutex == NULL) {
        perror("LockSocketMutex");

        exit(ERROR);
    }

    // Call pthread_mutex_init.  This version of CreateMutex just passes a
    // mutex handle for the function to initialize with NULL for the attributes.
    // We are using this instead of calling on mutex_core to avoid
    // extraneous dependencies.
    int nResult = pthread_mutex_init(g_pSocketMutex, NULL);
    if (OK != nResult) {
        // Cleanup the mutex handle if necessary
        if (NULL != g_pSocketMutex) {
            FreeSocketMutex();
        }
        perror("LockSocketMutex");
        exit(ERROR);
    }
}

///////////////////////////////////////////////////////////////////////////////
// FreeSocketMutex function - Releases operating system resources consumed
// by the socket mutex.
//

void FreeSocketMutex() {
    if (NULL == g_pSocketMutex) {
        // If we're here, assume that the socket mutex has already
        // been freed; therefore, we have nothing to do.
        return;
    }

    /* Destroy the mutex handle for socket use.  We are utilizing the
     * bare-bones pthread_mutex_t  type and pthread_mutex_destroy system API,
     * rather than the functions exported by the mutex_core library.  This is
     * to avoid an unncessary dependency.  That is, I do not want to have to
     * drag in the mutex library every single time I want to use this
     * inetsock_core library. */

    int nResult = pthread_mutex_destroy(g_pSocketMutex);
    if (nResult != OK) {
        perror("inetsock_core[FreeSocketMutex]");

        exit(ERROR);
    }

    free(g_pSocketMutex);
    g_pSocketMutex = NULL;
}

void LockSocketMutex() {
    int nResult = ERROR;

    if (NULL == g_pSocketMutex) {
        // just do nothing. (g_pSocketMutex will have the value of NULL in
        // the case that the caller of this library did not call
        // CreateSocketMutex in their main function)

        return; /* if we are here then we are not using mutexes at all */
    }

    nResult = pthread_mutex_lock(g_pSocketMutex);
    if (OK != nResult) {
        perror("LockSocketMutex");
        exit(ERROR);
    }

    return; 	// Succeeded
}

void UnlockSocketMutex() {
    if (NULL == g_pSocketMutex) {
        // If the g_pSocketMutex handle is NULL, then assume that the caller of
        // this library is writing a single-threaded application which will not
        // need mutexes for its socket communications. Therefore, in this case,
        // just do nothing. (g_pSocketMutex will have the value of NULL
        // in the case that the caller of this library did not call
        // CreateSocketMutex in their main function)

        return;
    }

    int nResult = pthread_mutex_unlock(g_pSocketMutex);
    if (OK != nResult) {
        perror("UnlockSocketMutex");
        exit(ERROR);
    }
}

/**
 * @brief Attempts to resolve the hostname or IP address provided with
 * the Domain Name System (DNS) and reports success or failure.
 * @param hostnameOrIP The hostname or IP address of the remote computer
 * that is to be resolved with DNS.
 * @param Address of a storage location that is to be filled with a
 *  hostent structure upon successful resolution of the hostname or 
 *  IP address provided.  
 * @returns Zero if resolution has failed; nonzero otherwise.
 * @remarks If this function returns nonzero, then the value of '*he'
 *  will be the address of a storage location containing a hostent
 *  structure containing information for the remote host.
 */
int IsHostnameValid(const char *hostnameOrIP, struct hostent **he) {
    if (IsNullOrWhiteSpace(hostnameOrIP)) {
        // The hostnameOrIP parameter cannot be blank, since we need to find
        // out if the hostname or IP supplied is valid.  Can't very well do that
        // for a blank value!
        return FALSE;
    }

    if (he == NULL) {
        // return FALSE if no storage location for the 'he' pointer passed
        return FALSE;
    }

    LockSocketMutex();
    {
        if ((*he = gethostbyname(hostnameOrIP)) == NULL) {
            *he = NULL;

            UnlockSocketMutex();

            // return FALSE if no storage location for the 'he' pointer passed
            return FALSE;
        }
    }
    UnlockSocketMutex();

    return TRUE;
}

/**
 * @brief Determines whether the socket file descriptor passed is valid.
 * @param nSocket An integer specifying the value of the file descriptor to be checked.
 * @returns TRUE if the descriptor is valid; FALSE otherwise.
 * @remarks "Valid" in this context simply means a positive integer.  This
 * function's job is not to tell you whether the socket is currently open
 * or closed.
 */
int IsSocketValid(int nSocket) {
    /* Linux socket file descriptors are always positive, nonzero
     * integers when they represent a valid socket handle.
     */
    if (nSocket <= 0) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Frees the memory at the address specified.
 * @param ppBuffer Address of a pointer which points to memory
 * allocated with the '*alloc' functions (malloc, calloc, realloc).
 * @remarks Remember to cast the address of the pointer being passed
 * to this function to void**
 */
void free_buffer(void **ppBuffer) {
    if (ppBuffer == NULL || *ppBuffer == NULL) {
        return;     // Nothing to do since there is no address referenced
    }

    free(*ppBuffer);
    *ppBuffer = NULL;
}

/**
 * @brief Reports the error message specified as well as the error from
 *  the system.  Closes the socket file descriptor provided in order to
 *   free operating system resources.  Exits the program with the ERROR exit
 *   code.
 * @param nSocket Socket file descriptor to be closed after the error
 *  has been reported.
 * @param msg Additional error text to be echoed to the console.
 **/
void error_and_close(int nSocket, const char *msg) {
    if (msg == NULL || strlen(msg) == 0 || msg[0] == '\0') {
        perror(NULL);
        exit(ERROR);
        return;   // This return statement might not fire, but just in case.
    }

    LogError(msg);
    perror(NULL);

    if (nSocket > 0) {
        close(nSocket);
        fprintf(stderr, "Exiting with error code %d.", ERROR);
    }

    exit(ERROR);
}

/**
 * @brief Reports the error message specified as well as the error from
 *  the system. Exits the program with the ERROR exit code.
 * @param msg Additional error text to be echoed to the console.
 **/
void error(const char* msg) {
    if (msg == NULL || strlen(msg) == 0 || msg[0] == '\0') {
        return;
    }

    LogError(msg);
    perror(NULL);
    exit(ERROR);
}

/**
 * @brief Creates a new socket endpoint for communicating with a remote
 *  host over TCP/IP.
 * @returns Socket file descriptor which provides a handle to the newly-
 *  created socket endpoint.
 * @remarks If an error occurs, prints the error to the console and forces
 *  the program to exit with the ERROR exit code.
 */
int CreateSocket() {
    int nSocket = -1;

    LockSocketMutex();
    {
        nSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (!IsSocketValid(nSocket)) {
            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }
    }
    UnlockSocketMutex();

    SetSocketReusable(nSocket);

    return nSocket;
}

void SetSocketNonBlocking(int nSocket) {

    if (!IsSocketValid(nSocket)) {
        return;
    }

    int flags = 0;

    /* Set socket to non-blocking */

    if ((flags = fcntl(nSocket, F_GETFL, 0)) < 0) {
        return;
    }

    if (fcntl(nSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
        return;
    }
}

int SetSocketReusable(int nSocket) {
    int retval = ERROR;

    if (!IsSocketValid(nSocket)) {

        return retval;
    }

    // Set socket options to allow the socket to be reused.
    LockSocketMutex();
    {
        retval = setsockopt(nSocket, SOL_SOCKET, SO_REUSEADDR, &(int ) {
                    1 }, sizeof(int));
        if (retval < 0) {
            perror("setsockopt");

            UnlockSocketMutex();

            return retval;
        }
    }
    UnlockSocketMutex();

    return retval;
}

/**
 * @brief Populates the port and address information for a server
 * so the server knows the hostname/IP address and port of the computer
 * it is listening on.
 * @param port String containing the port number to listen on.  Must be numeric.
 * @param hostnameOrIp String containing the hostname or IP address of the
 * server computer.  Can be NULL, in which case, htons(INADDR_ANY) will be set.
 * Use NULL for a sevrer, and a specific value for a client.
 * @param addr Address of storage that will receive a filled-in sockaddr_in
 * structure that defines the server endpoint.
 * @remarks If invalid input is supplied or an error occurs, reports
 * these problems to the console and forces the program to die with the
 * ERROR exit code.
 */
void GetServerAddrInfo(const char *port, struct sockaddr_in *addr) {
    LockSocketMutex();
    {
        if (IsNullOrWhiteSpace(port)) {
            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        if (addr == NULL) {
            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        // Get the port number from its string representation and then
        // validate that it is in the proper range
        int portnum = 0;
        int result = StringToLong(port, (long*) &portnum);
        if (result >= 0 && !IsUserPortValid(portnum)) {

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        // Populate the fields of the sockaddr_in structure passed to us
        // with the proper values.
        addr->sin_family = AF_INET;
        addr->sin_port = htons(portnum);
        addr->sin_addr.s_addr = htons(INADDR_ANY);
    }
    UnlockSocketMutex();
}

/**
 * @brief Binds a server socket to the address and port specified by the 'addr'
 * parameter.
 * @param nSocket Socket file descriptor that references the socket to be bound.
 * @param addr Pointer to a sockaddr_in structure that specifies the host
 * and port to which the socket endpoint should be bound.
 */
int BindSocket(int nSocket, struct sockaddr_in *addr) {
    int retval = ERROR;

    LockSocketMutex();
    {
        if (!IsSocketValid(nSocket)) {
            errno = EBADF;

            perror("BindSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        if (addr == NULL) {
            errno = EINVAL; // addr param required

            perror("BindSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        retval = bind(nSocket, (struct sockaddr*) addr, sizeof(*addr));
        if (retval < 0) {
            perror("BindSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }
    }
    UnlockSocketMutex();

    return retval;
}

/**
 * @brief Sets up a TCP or UDP server socket to listen on a port and IP address
 * to which it has been bound previously with the BindSocket function.
 * @params nSocket Socket file descriptor.
 * @returns ERROR if the socket file descriptor passed in nSocket
 * does not represent a valid, open socket and sets errno to EBADF.  Otherwise,
 * returns the result of calling listen on the socket file descriptor
 * passed with a backlog size of BACKLOG_SIZE (128 by default).  Zero is
 * returned if the operation was successful.
 */
int ListenSocket(int nSocket) {
    int retval = ERROR;

    LockSocketMutex();
    {
        if (!IsSocketValid(nSocket)) {
            errno = EBADF;

            perror("ListenSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        retval = listen(nSocket, BACKLOG_SIZE);

        if (retval < 0) {
            perror("ListenSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }
    }
    UnlockSocketMutex();

    return retval;
}

/**
 * @brief Accepts an incoming connection on a socket and returns information
 * about the remote host.
 * @param nSocket Socket file descriptor on which to accept new incoming
 * connections.
 * @param addr Reference to a sockaddr_in structure that receives information
 * aboutthe IP address of the remote endpoint.
 * @returns Socket file descriptor representing the local endpoint of the new
 * incoming connection; or a negative number indicating that errno should be
 * read for the error description.
 * @remarks Returns ERROR if any of the following are true: (a) sets errno
 * to EBADF if nSocket is an invalid value (nonpositive) or (b) sets errno to
 * EINVAL if addr is NULL. This function blocks the calling thread until an
 * incoming connection has been  established.
 */
int AcceptSocket(int nSocket, struct sockaddr_in *pSockAddr) {

    int nClientSocket = ERROR;

    if (!IsSocketValid(nSocket)) {
        errno = EBADF;

        perror("AcceptSocket");

        FreeSocketMutex();

        exit(ERROR);
    }

    if (pSockAddr == NULL) {
        errno = EINVAL;

        perror("AcceptSocket");

        FreeSocketMutex();

        CloseSocket(nSocket);

        exit(ERROR);
    }

    // We now call the accept function.  This function holds us up
    // until a new client connection comes in, whereupon it returns
    // a file descriptor that represents the socket on our side that
    // is connected to the client.
    socklen_t client_address_len = sizeof(*pSockAddr);

    if ((nClientSocket = accept(nSocket, (struct sockaddr*) pSockAddr,
            &client_address_len)) < 0) {
        if (EBADF != errno) {
            perror("AcceptSocket");

            FreeSocketMutex();

            CloseSocket(nSocket);
        }

        /* If errno is EBADF, this is just from a thread being terminated
         * outside of this accept() call. In this case, merely return an
         * invalid socket file descriptor value instead of forcibly
         * terminating the program.  If errno is anything else
         * besides EBADF, then forcibly exit. */

        if (EBADF == errno) {
            return ERROR;
        } else {
            exit(ERROR);
        }
    }

    return nClientSocket;
}

/**
 * @brief Reads a line of data, terminated by the '\n' character, from a socket.
 * @param nSocket Socket file descriptor from which to receive data.
 * @param buf Reference to an address at which to allocate storage
 * for the received data.
 * @returns Total bytes read for the current line or a negative number
 * otherwise.
 * @remarks This function will forcibly terminate the calling program
 * with an exit code of ERROR if the operation fails.  It is the responsibility
 * of the caller to free the memory referenced by *buf.  The caller must always
 * pass NULL for buf.  If valid storage is passed, this function will free the
 * storage referenced by *buf and allocate brand-new storage for the incoming
 * line.
 */
int Receive(int nSocket, char **ppszReceiveBuffer) {
    int nTotalBytesRead = 0;

    // Can't do anything if the receive buffer's memory address is not
    // given
    if (ppszReceiveBuffer == NULL) {
        return 0;
    }

    if (!IsSocketValid(nSocket)) {
        // If an invalid socket file descriptor is passed, we don't care.
        // Could be a socket that is polled even after it's already been
        // closed and its descriptor invalidated.  Just finish and return
        // zero bytes received.
        return 0;
    }

    int bytes_read = 0;

    // Allocate up some brand-new storage of size RECV_BLOCK_SIZE
    // plus an extra slot to hold the null-terminator.  Free any
    // storage already referenced by *buf.  If *buf happens to be
    // NULL already, a malloc is done.  Once the new memory has been
    // allocated, we then explicitly zero it out.
    int nInitialReceiveBufferSize = RECV_BLOCK_SIZE + 1;

    nTotalBytesRead = 0;
    *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
            nInitialReceiveBufferSize * sizeof(char));
    explicit_bzero((void*) *ppszReceiveBuffer, nInitialReceiveBufferSize);

    while (1) {
        char ch;		// receive one char at a time until a newline is found
        bytes_read = recv(nSocket, &ch, RECV_BLOCK_SIZE, RECV_FLAGS);
        if (bytes_read < 0) {
            if (errno == EBADF || errno == EWOULDBLOCK) {
                sleep(1); /* allow any other threads receiving to run */
                continue;
            } else {
                break;
            }
        }

        // If we are here, then stuff came over the wire.
        // Stick the character received, from ch, into the next
        // storage element referenced by *buf + total_read
        // and then allocate some more memory to hold the
        // next char and then the null terminator
        *(*ppszReceiveBuffer + nTotalBytesRead) = ch;

        // Tally the total bytes read overall
        nTotalBytesRead += bytes_read;

        // If the newline ('\n') character was the char received,
        // then we're done; it's time to apply the null terminator.
        if (ch == '\n') {
            break;
        }

        // re-allocate more memory and make sure to leave room
        // for the null-terminator.

        int new_recv_buffer_size = (nTotalBytesRead + RECV_BLOCK_SIZE + 1)
                * sizeof(char);

        *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
                new_recv_buffer_size);
    }

    if (nTotalBytesRead > 0) {
        // We are done receiving, cap the string off with a null terminator
        // after resizing the buffer to match the total bytes read + 1.  if
        // a connection error happened prior to reading even one byte, then
        // total_read will be zero and the call below will be equivalent to
        // free.  strlen(*buf) will then return zero, and this will be
        // how we can tell not to call free() again on *buf

        *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
                (nTotalBytesRead + 1) * sizeof(char));

        // cap the buffer off with the null-terminator
        *(*ppszReceiveBuffer + nTotalBytesRead) = '\0';
    } else {
        // Error occurred or the other end terminated the connection.

        free_buffer((void**) ppszReceiveBuffer);

        return 0;
    }

    // Now the storage at address *buf should contain the entire
    // line just received, plus the newline and the null-terminator, plus
    // any previously-received data
    return nTotalBytesRead;
}

/**
 * @brief Helper function to guarantee that entire message provided gets
 * sent over a socket.
 * @param nSocket File descriptor for the socket.  Socket must be in the
 * connected state.
 * @param pszMessage Reference to the start of the buffer containing the message
 * to be sent.
 * @param nLength Size of the buffer to be used for sending.
 * @return Total number of bytes sent, or -1 if an error occurred.
 * @remarks This function will kill the program after spitting out an error
 * message if something goes wrong.
 */
int SendAll(int nSocket, const char *pszMessage, size_t nLength) {
    int nTotalBytesSent = 0;

    // Make sure we have a valid socket file descriptor
    if (!IsSocketValid(nSocket)) {
        errno = EBADF;

        perror("SendAll");

        FreeSocketMutex();

        exit(ERROR);
    }

    if (pszMessage == NULL || ((char*) pszMessage)[0] == '\0'
            || strlen((char*) pszMessage) == 0) {
        errno = EINVAL;

        perror("SendAll");

        FreeSocketMutex();

        exit(ERROR);
    }

    char trimmed_message[strlen(pszMessage) + 1];
    Trim(trimmed_message, strlen(pszMessage) + 1, pszMessage);

    if ((int) nLength <= 0) {
        errno = EINVAL;

        perror("SendAll");

        FreeSocketMutex();

        exit(ERROR);
    }

    char *ptr = (char*) pszMessage;

    int nBytesRemaining = (int) nLength;

    while (nTotalBytesSent < nBytesRemaining) {
        int nBytesSent = send(nSocket, ptr, nLength, 0);

        if (nBytesSent < 1) {
            perror("SendAll");

            FreeSocketMutex();

            exit(ERROR);
        }

        nTotalBytesSent += nBytesSent;

        ptr += nBytesSent;
        nBytesRemaining -= nBytesSent;
    }

    return nTotalBytesSent;
}

int Send(int nSocket, const char *pszMessage) {
    if (!IsSocketValid(nSocket)) {
        errno = EBADF;

        exit(ERROR);
    }

    if (IsNullOrWhiteSpace(pszMessage)) {
        // Nothing to send
        return 0;
    }
    int nMessageLength = strlen(pszMessage);

    int bytes_sent = SendAll(nSocket, pszMessage, nMessageLength);

    if (bytes_sent < 0) {
        error_and_close(nSocket, "Send: Failed to send data.");

        FreeSocketMutex();

        exit(ERROR);
    }

    return bytes_sent;
}

/**
 * @brief Connects a socket to a remote host whose hostname or IP address and
 * port number is specified.
 * @param nSocket Socket file descriptor representing a socket that is not yet
 * connected to a remote endpoint.
 * @param pszHostName String indicating the human-readable (in DNS) hostname
 * or the IP address of the remote host.
 * @param nPort Port number that the service on the remote host is listening on.
 * @returns Zero if successful; ERROR if an error occurred.  The errno
 * value should be examined if this happens.  In other cases, this function
 * forcibly terminates the calling program with the ERROR exit code.
 */
int ConnectSocket(int nSocket, const char *pszHostName, int nPort) {
    int result = ERROR;

    if (!IsSocketValid(nSocket)) {
        exit(result);
    }

    if (!IsUserPortValid(nPort)) {
        if (stderr != GetErrorLogFileHandle()) {
            fprintf(stderr,
                    "ConnectSocket: An invalid value is being used for the "
                            "port number of the server.");
        }

        CloseSocket(nSocket);

        FreeSocketMutex();

        exit(result);
    }

    struct hostent *he;						// Host entry
    struct sockaddr_in server_address; 		// Structure for the server
                                            // address and port

    // First, try to resolve the host name or IP address passed to us,
    // to ensure that the host can even be found on the network in the first
    // place.  Calling the function below also has the added bonus of
    // filling in a hostent structure for us if it succeeds.
    if (!IsHostnameValid(pszHostName, &he)) {
        if (GetErrorLogFileHandle() != stderr) {
            fprintf(stderr, "ConnectSocket: Cannot connect to server on '%s'.",
                    pszHostName);
        }

        CloseSocket(nSocket);

        FreeSocketMutex();

        exit(result);
    }

    LockSocketMutex();
    {
        /* copy the network address to sockaddr_in structure */
        memcpy(&server_address.sin_addr, he->h_addr_list[0], he->h_length);
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(nPort);

        if ((result = connect(nSocket, (struct sockaddr*) &server_address,
                sizeof(server_address))) < 0) {
            UnlockSocketMutex();

            FreeSocketMutex();

            CloseSocket(nSocket);

            /* If we are logging to a file and not the screen, print a message on the
             * screen for an interactive user that the connect operation failed. */
            if (GetLogFileHandle() != stdout) {
                fprintf(stdout, CONNECT_OPERATION_FAILED, pszHostName, nPort);
            }

            CloseLogFileHandles();

            exit(ERROR);
        }
    }
    UnlockSocketMutex();

    return result;
}

void CloseSocket(int nSocket) {
    if (!IsSocketValid(nSocket)) {
        return;	// just silently fail if the socket file descriptor passed is invalid
    }

    if (OK != shutdown(nSocket, SHUT_RD)) {
        /* This is not really an error, since shutting down a socket
         * really just means disabling reads/writes on an open socket,
         * not closing it.  Who cares if we cannot perform this
         * operation? */

        LogWarning("CloseSocket: Failed to shut down the socket with file "
                "descriptor %d.", nSocket);
    }

    int retval = close(nSocket);

    if (retval < 0) {
        return;
    }
}
