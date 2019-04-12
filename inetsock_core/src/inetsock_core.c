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
 * @param sockFd An integer specifying the value of the file descriptor to be checked.
 * @returns TRUE if the descriptor is valid; FALSE otherwise.
 * @remarks "Valid" in this context simply means a positive integer.  This
 * function's job is not to tell you whether the socket is currently open
 * or closed.
 */
int IsSocketValid(int sockFD) {
    /* Linux socket file descriptors are always positive, nonzero
     * integers when they represent a valid socket handle.
     */
    if (sockFD <= 0) {
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
    LogDebug("In free_buffer");

    LogInfo("free_buffer: Checking pointer provided...");

    if (ppBuffer == NULL || *ppBuffer == NULL) {
        LogWarning("free_buffer: No memory has been passed to work on.  "
                "Nothing to do.");

        LogDebug("free_buffer: Done.");

        return;     // Nothing to do since there is no address referenced
    }

    LogInfo("free_buffer: Freeing the memory referenced by the ppBuffer "
            "parameter...");

    free(*ppBuffer);
    *ppBuffer = NULL;

    LogDebug("free_buffer: Done.");
}

/**
 * @brief Reports the error message specified as well as the error from
 *  the system.  Closes the socket file descriptor provided in order to
 *   free operating system resources.  Exits the program with the ERROR exit
 *   code.
 * @param sockFd Socket file descriptor to be closed after the error
 *  has been reported.
 * @param msg Additional error text to be echoed to the console.
 **/
void error_and_close(int sockFd, const char *msg) {
    if (msg == NULL || strlen(msg) == 0 || msg[0] == '\0') {
        perror(NULL);
        exit(ERROR);
        return;   // This return statement might not fire, but just in case.
    }

    LogError(msg);
    perror(NULL);

    if (sockFd > 0) {
        close(sockFd);
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
    LogDebug("In CreateSocket");

    int sockFd = -1;

    LogInfo("CreateSocket: Attempting to obtain a lock on the socket mutex...");

    LockSocketMutex();
    {
        LogInfo("CreateSocket: Socket mutex lock obtained, or we are "
                "not using it.");

        LogInfo("CreateSocket: Attempting to create new TCP endpoint...");

        sockFd = socket(AF_INET, SOCK_STREAM, 0);
        if (!IsSocketValid(sockFd)) {
            LogError("CreateSocket: Could not create new TCP endpoint.");

            UnlockSocketMutex();

            FreeSocketMutex();

            LogDebug("CreateSocket: Done.");

            exit(ERROR);
        }

        LogDebug(
                "CreateSocket: Attempting to release the socket mutex lock...");
    }
    UnlockSocketMutex();

    LogDebug("CreateSocket: Socket mutex lock released.");

    LogInfo("CreateSocket: Endpoint created successfully.");

    LogInfo("CreateSocket: Attempting to mark endpoint as reusable...");

    SetSocketReusable(sockFd);

    LogInfo("CreateSocket: Endpoint configured to be reusable.");

    LogInfo("CreateSocket: The new socket file descriptor is %d.", sockFd);

    LogDebug("CreateSocket: Done.");

    return sockFd;
}

void SetSocketNonBlocking(int sockFd) {

    if (!IsSocketValid(sockFd)) {
        return;
    }

    int flags = 0;

    /* Set socket to non-blocking */

    if ((flags = fcntl(sockFd, F_GETFL, 0)) < 0) {
        return;
    }

    if (fcntl(sockFd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return;
    }
}

int SetSocketReusable(int sockFd) {
    LogDebug("In SetSocketReusable");

    int retval = ERROR;

    LogInfo("SetSocketReusable: Checking whether a valid socket file "
            "descriptor was passed...");

    if (!IsSocketValid(sockFd)) {
        LogError("SetSocketReusable: The socket file descriptor has an "
                "invalid value.");

        LogDebug("SetSocketReusable: Done.");

        return retval;
    }

    LogInfo("SetSocketReusable: A valid socket file descriptor has "
            "been passed.");

    LogDebug("SetSocketReusable: Attempting to obtain a lock on the "
            "socket mutex...");

    // Set socket options to allow the socket to be reused.
    LockSocketMutex();
    {
        LogDebug("SetSocketReusable: Socket mutex lock obtained, "
                "or not using it.");

        LogInfo("SetSocketReusable: Attempting to set the socket as "
                "reusable...");

        retval = setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &(int ) {
                    1 }, sizeof(int));
        if (retval < 0) {
            perror("setsockopt");

            LogError("SetSocketReusable: Failed to mark socket as reusable.");

            LogDebug("SetSocketReusable: Attempting to release the socket"
                    " mutex lock...");

            UnlockSocketMutex();

            LogDebug("SetSocketReusable: Socket mutex lock has been released.");

            LogDebug("SetSocketReusable: Done.");

            return retval;
        }

        LogInfo("SetSocketReusable: Socket configuration operation succeeded.");

        LogDebug("SetSocketReusable: Attempting to release the socket "
                "mutex lock...");
    }
    UnlockSocketMutex();

    LogDebug("SetSocketReusable: Socket mutex lock released.");

    LogDebug("SetSocketReusable: retval = %d", retval);

    LogDebug("SetSocketReusable: Done.");

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

    LogInfo("In GetServerAddrInfo");

    LogDebug("GetServerAddrInfo: Obtaining a lock on the socket mutex...");

    LockSocketMutex();
    {
        LogDebug("GetServerAddrInfo: Lock obtained on socket mutex or "
                "it's not needed.");

        LogInfo("GetServerAddrInfo: port = '%s'", port);

        LogInfo("GetServerAddrInfo: Checking whether the 'port' "
                "parameter has a value...");

        if (IsNullOrWhiteSpace(port)) {
            LogError("GetServerAddrInfo: String containing the port number "
                    "is blank.");

            LogDebug("GetServerAddrInfo: Attempting to release the socket "
                    "mutex lock...");

            UnlockSocketMutex();

            LogDebug("GetServerAddrInfo: Socket mutex lock has been released.");

            LogDebug("GetServerAddrInfo: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("GetServerAddrInfo: Socket mutex resources freed.");

            LogDebug("GetServerAddrInfo: Done.");

            exit(ERROR);
        }

        if (addr == NULL) {
            LogError("GetServerAddrInfo: Missing pointer to a sockaddr_in "
                    "structure.");

            LogDebug("GetServerAddrInfo: Attempting to release the socket "
                    "mutex lock...");

            UnlockSocketMutex();

            LogDebug("GetServerAddrInfo: Socket mutex lock has been released.");

            LogDebug("GetServerAddrInfo: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("GetServerAddrInfo: Socket mutex resources freed.");

            LogDebug("GetServerAddrInfo: Done.");

            exit(ERROR);
        }

        // Get the port number from its string representation and then
        // validate that it is in the proper range
        int portnum = 0;
        int result = StringToLong(port, (long*) &portnum);
        if (result >= 0 && !IsUserPortValid(portnum)) {
            LogError("GetServerAddrInfo: Port number must be in the range "
                    "1024-49151 inclusive.");

            LogDebug("GetServerAddrInfo: Attempting to release the socket "
                    "mutex lock...");

            UnlockSocketMutex();

            LogDebug("GetServerAddrInfo: Socket mutex lock has been released.");

            LogDebug("GetServerAddrInfo: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("GetServerAddrInfo: Socket mutex resources freed.");

            LogDebug("GetServerAddrInfo: Done.");

            exit(ERROR);
        }

        // Populate the fields of the sockaddr_in structure passed to us
        // with the proper values.

        LogInfo("GetServerAddrInfo: Configuring server address and port...");

        addr->sin_family = AF_INET;
        addr->sin_port = htons(portnum);
        addr->sin_addr.s_addr = htons(INADDR_ANY);

        LogInfo("GetServerAddrInfo: Server configured to listen on port %d.",
                portnum);

        LogDebug("GetServerAddrInfo: Attempting to release the socket "
                "mutex lock...");
    }
    UnlockSocketMutex();

    LogDebug("GetServerAddrInfo: The socket mutex lock has been released.");

    LogDebug("GetServerAddrInfo: Done.");
}

/**
 * @brief Binds a server socket to the address and port specified by the 'addr'
 *   parameter.
 * @param sockFd Socket file descriptor that references the socket to be bound.
 * @param addr Pointer to a sockaddr_in structure that specifies the host
 * and port to which the socket endpoint should be bound.
 */
int BindSocket(int sockFd, struct sockaddr_in *addr) {
    LogDebug("In BindSocket");

    int retval = ERROR;

    LockSocketMutex();
    {
        LogDebug("BindSocket: sockFd = %d", sockFd);

        LogInfo("BindSocket: Checking whether a valid socket file "
                "descriptor was passed...");

        if (!IsSocketValid(sockFd)) {
            LogError("BindSocket: Invalid socket file descriptor passed.");

            errno = EBADF;

            LogDebug("BindSocket: Set errno = %d", errno);

            perror("BindSocket");

            LogDebug("BindSocket: Attempting to release the socket mutex "
                    "lock...");

            UnlockSocketMutex();

            LogDebug("BindSocket: Socket mutex lock has been released.");

            LogDebug("BindSocket: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("BindSocket: Socket mutex resources freed.");

            LogDebug("BindSocket: Done.");

            exit(ERROR);
        }

        LogInfo("BindSocket: A valid socket file descriptor has been passed.");

        LogInfo("BindSocket: Checking whether a valid sockaddr_in "
                "reference has been passed...");

        if (addr == NULL) {
            LogError("BindSocket: A null reference has been passed for the "
                    "'addr' parameter.  Nothing to do.");

            errno = EINVAL; // addr param required

            LogDebug("BindSocket: Set errno = %d", errno);

            perror("BindSocket");

            LogDebug("BindSocket: Attempting to release the socket "
                    "mutex lock...");

            UnlockSocketMutex();

            LogDebug("BindSocket: Socket mutex lock has been released.");

            LogDebug("BindSocket: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("BindSocket: Socket mutex resources freed.");

            LogDebug("BindSocket: Done.");

            exit(ERROR);
        }

        LogInfo("BindSocket: A valid sockaddr_in reference has been passed.");

        LogInfo("BindSocket: Attempting to bind socket %d to "
                "the server address...", sockFd);

        retval = bind(sockFd, (struct sockaddr*) addr, sizeof(*addr));

        LogDebug("BindSocket: retval = %d", retval);

        if (retval < 0) {
            LogError("BindSocket: Failed to bind socket.");

            LogDebug("BindSocket: errno = %d", errno);

            perror("BindSocket");

            LogDebug("BindSocket: Attempting to release the socket "
                    "mutex lock...");

            UnlockSocketMutex();

            LogDebug("BindSocket: Socket mutex lock has been released.");

            LogDebug("BindSocket: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("BindSocket: Socket mutex resources freed.");

            LogDebug("BindSocket: Done.");

            exit(ERROR);
        }

        LogInfo("BindSocket: Successfully bound the server socket.");

        LogDebug("BindSocket: Attemtping to release the socket mutex lock...");
    }
    UnlockSocketMutex();

    LogDebug("BindSocket: Released the socket mutex lock.");

    LogInfo("BindSocket: Returning %d", retval);

    LogDebug("BindSocket: Done.");

    return retval;
}

/**
 * @brief Sets up a TCP or UDP server socket to listen on a port and IP address
 * to which it has been bound previously with the BindSocket function.
 * @params sockFd Socket file descriptor.
 * @returns ERROR if the socket file descriptor passed in sockFd
 * does not represent a valid, open socket and sets errno to EBADF.  Otherwise,
 * returns the result of calling listen on the socket file descriptor
 * passed with a backlog size of BACKLOG_SIZE (128 by default).  Zero is
 * returned if the operation was successful.
 */
int ListenSocket(int sockFd) {
    LogInfo("In ListenSocket");

    int retval = ERROR;

    LogDebug(
            "ListenSocket: Attempting to obtain a lock on the socket mutex...");

    LockSocketMutex();
    {
        LogDebug("ListenSocket: Socket mutex has been locked.");

        LogInfo("ListenSocket: Checking for a valid socket file descriptor...");

        LogDebug("ListenSocket: sockFd = %d", sockFd);

        if (!IsSocketValid(sockFd)) {
            LogError("ListenSocket: Invalid socket file descriptor passed.");

            errno = EBADF;

            LogDebug("ListenSocket: Set errno = %d", errno);

            perror("ListenSocket");

            LogDebug("ListenSocket: Attempting to release the socket mutex "
                    "lock...");

            UnlockSocketMutex();

            LogDebug("ListenSocket: Socket mutex lock has been released.");

            LogDebug("ListenSocket: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("ListenSocket: Socket mutex resources freed.");

            LogDebug("ListenSocket: Done.");

            exit(ERROR);
        }

        LogDebug("ListenSocket: A valid socket file descriptor has been "
                "passed.");

        LogInfo("ListenSocket: Calling the listen function...");

        retval = listen(sockFd, BACKLOG_SIZE);

        LogDebug("ListenSocket: The listen function has been called.");

        LogDebug("ListenSocket: retval = %d", retval);

        if (retval < 0) {
            LogError("ListenSocket: Failed to listen on socket.");

            perror("ListenSocket");

            LogDebug("ListenSocket: Attempting to release the socket "
                    "mutex lock...");

            UnlockSocketMutex();

            LogDebug("ListenSocket: Socket mutex lock has been released.");

            LogDebug("ListenSocket: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("ListenSocket: Socket mutex resources freed.");

            LogDebug("ListenSocket: Done.");

            exit(ERROR);
        }

        LogInfo("ListenSocket: Listen operation successful.");

        LogDebug("ListenSocket: Releasing the socket mutex lock...");
    }
    UnlockSocketMutex();

    LogDebug("ListenSocket: Socket mutex lock released.");

    LogInfo("ListenSocket: Returning %d", retval);

    LogDebug("ListenSocket: Done.");

    return retval;
}

/**
 * @brief Accepts an incoming connection on a socket and returns information
 * about the remote host.
 * @param sockFd Socket file descriptor on which to accept new incoming
 * connections.
 * @param addr Reference to a sockaddr_in structure that receives information
 * aboutthe IP address of the remote endpoint.
 * @returns Socket file descriptor representing the local endpoint of the new
 * incoming connection; or a negative number indicating that errno should be
 * read for the error description.
 * @remarks Returns ERROR if any of the following are true: (a) sets errno
 * to EBADF if sockFd is an invalid value (nonpositive) or (b) sets errno to
 * EINVAL if addr is NULL. This function blocks the calling thread until an
 * incoming connection has been  established.
 */
int AcceptSocket(int nSocket, struct sockaddr_in *pSockAddr) {

    LogDebug("In AcceptSocket");

    int nClientSocket = ERROR;

    LogDebug("AcceptSocket: sockFd = %d", nSocket);

    LogInfo("AcceptSocket: Checking for a valid socket file descriptor...");

    if (!IsSocketValid(nSocket)) {
        LogError("AcceptSocket: Invalid file descriptor passed in "
                "sockFd parameter.");

        errno = EBADF;

        perror("AcceptSocket");

        LogDebug("AcceptSocket: Attempting to free socket mutex resources...");

        FreeSocketMutex();

        LogDebug("AcceptSocket: Socket mutex resources freed.");

        LogDebug("AcceptSocket: Done.");

        exit(ERROR);
    }

    LogInfo("AcceptSocket: We were passed a valid socket file descriptor.");

    LogInfo("AcceptSocket: Checking whether we are passed a valid sockaddr_in "
            "reference...");

    if (pSockAddr == NULL) {
        LogError(
                "AcceptSocket: Null reference passed for sockaddr_in structure."
                        "  Stopping.");

        errno = EINVAL;

        perror("AcceptSocket");

        LogDebug("AcceptSocket: Attempting to free socket mutex resources...");

        FreeSocketMutex();

        LogDebug("AcceptSocket: Socket mutex resources freed.");

        LogDebug("AcceptSocket: Attempting to close the server endpoint...");

        CloseSocket(nSocket);

        LogDebug("AcceptSocket: Server endpoint resources released.");

        LogDebug("AcceptSocket: Done.");

        exit(ERROR);
    }

    LogInfo("AcceptSocket: We have a valid reference to a sockaddr_in "
            "structure.");

    // We now call the accept function.  This function holds us up
    // until a new client connection comes in, whereupon it returns
    // a file descriptor that represents the socket on our side that
    // is connected to the client.
    LogInfo("AcceptSocket: Calling accept...");

    socklen_t client_address_len = sizeof(*pSockAddr);

    if ((nClientSocket = accept(nSocket, (struct sockaddr*) pSockAddr,
            &client_address_len)) < 0) {
        LogError("AcceptSocket: Invalid value returned from accept.");

        if (EBADF != errno) {
            perror("AcceptSocket");

            LogDebug("AcceptSocket: Attempting to free socket mutex "
                    "resources...");

            FreeSocketMutex();

            LogDebug("AcceptSocket: Socket mutex resources freed.");

            LogDebug("AcceptSocket: Attempting to close the server "
                    "endpoint...");

            CloseSocket(nSocket);

            LogDebug("AcceptSocket: Server endpoint resources released.");
        }

        LogDebug("AcceptSocket: Done.");

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

    LogInfo("AcceptSocket: New client connected.");

    LogDebug("AcceptSocket: client_socket = %d", nClientSocket);

    LogDebug("AcceptSocket: Done.");

    return nClientSocket;
}

/**
 * @brief Reads a line of data, terminated by the '\n' character, from a socket.
 * @param sockFd Socket file descriptor from which to receive data.
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
int Receive(int sockFd, char **ppszReceiveBuffer) {
    LogDebug("In Receive");

    int total_read = 0;

    LogInfo("Receive: Checking whether the socket file descriptor "
            "passed is valid...");

    LogDebug("Receive: sockFd = %d", sockFd);

    if (!IsSocketValid(sockFd)) {
        LogError("Receive: Invalid socket file descriptor passed.");

        // If an invalid socket file descriptor is passed, we don't care.
        // Could be a socket that is polled even after it's already been
        // closed and its descriptor invalidated.  Just finish and return
        // zero bytes received.
        LogDebug("Receive: Returning zero bytes received.");

        LogDebug("Receive: Done.");

        return 0;
    }

    LogInfo("Receive: The socket file descriptor passed is valid.");

    LogInfo("Receive: Checking for valid receive buffer...");

    if (ppszReceiveBuffer == NULL) {
        LogError("Receive: Null reference passed for receive buffer.");

        LogDebug("Receive: Returning zero bytes received.");

        LogDebug("Receive: Done.");

        return 0;
    }

    LogInfo("Receive: Valid memory storage reference passed for "
            "receive buffer.");

    LogInfo("Receive: Initializing the receive buffer...");

    int bytes_read = 0;

    // Allocate up some brand-new storage of size RECV_BLOCK_SIZE
    // plus an extra slot to hold the null-terminator.  Free any
    // storage already referenced by *buf.  If *buf happens to be
    // NULL already, a malloc is done.  Once the new memory has been
    // allocated, we then explicitly zero it out.
    int initial_recv_buffer_size = RECV_BLOCK_SIZE + 1;

    LogInfo("Receive: Allocating %d B for receive buffer...",
            initial_recv_buffer_size);

    total_read = 0;
    *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
            initial_recv_buffer_size * sizeof(char));
    explicit_bzero((void*) *ppszReceiveBuffer, initial_recv_buffer_size);

    LogInfo("Receive: Allocated %d B for receive buffer.",
            initial_recv_buffer_size);

    //char prevch = '\0';
    while (1) {
        char ch;		// receive one char at a time
        bytes_read = recv(sockFd, &ch, RECV_BLOCK_SIZE, RECV_FLAGS);
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
        *(*ppszReceiveBuffer + total_read) = ch;

        // Tally the total bytes read overall
        total_read += bytes_read;

        // If the newline ('\n') character was the char received,
        // then we're done; it's time to apply the null terminator.
        if (ch == '\n') {
            //log_info("Receive: Newline encountered.");

            //log_info("Receive: Breaking out of recv loop...");

            break;
        }

        // re-allocate more memory and make sure to leave room
        // for the null-terminator.

        int new_recv_buffer_size = (total_read + RECV_BLOCK_SIZE + 1)
                * sizeof(char);

        *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
                new_recv_buffer_size);
    }

    LogInfo("Receive: %d B have been received.", total_read);

    LogInfo("Receive: Checking whether bytes received is a positive "
            "quantity...");

    if (total_read > 0) {
        LogInfo("Receive: Bytes received is a positive quantity.");

        // We are done receiving, cap the string off with a null terminator
        // after resizing the buffer to match the total bytes read + 1.  if
        // a connection error happened prior to reading even one byte, then
        // total_read will be zero and the call below will be equivalent to
        // free.  strlen(*buf) will then return zero, and this will be
        // how we can tell not to call free() again on *buf

        *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
                (total_read + 1) * sizeof(char));

        // cap the buffer off with the null-terminator
        *(*ppszReceiveBuffer + total_read) = '\0';

        LogDebug("Receive: Finished placing content into receive buffer.");
    } else {
        LogError("Receive: Total bytes received is a negative quantity.");

        LogInfo("Receive: Freeing memory allocated for receiving text...");

        free_buffer((void**) ppszReceiveBuffer);

        LogInfo("Receive: Memory for receiving text has been released.");

        return 0;
    }

    // Now the storage at address *buf should contain the entire
    // line just received, plus the newline and the null-terminator, plus
    // any previously-received data

    LogDebug("Receive: Returning %d (total B read)", total_read);

    LogDebug("Receive: Done.");

    return total_read;
}

/**
 * @brief Helper function to guarantee that entire message provided gets
 * sent over a socket.
 * @param sockFd File descriptor for the socket.  Socket must be in the
 * connected state.
 * @param buffer Reference to the start of the buffer containing the message
 * to be sent.
 * @param length Size of the buffer to be used for sending.
 * @return Total number of bytes sent, or -1 if an error occurred.
 * @remarks This function will kill the program after spitting out an error
 * message if something goes wrong.
 */
int SendAll(int sockFd, const char *message, size_t length) {
    LogDebug("In SendAll");

    int total_bytes_sent = 0;

    LogDebug("SendAll: Checking whether socket file descriptor is a "
            "valid value...");

    LogDebug("SendAll: sockFd = %d", sockFd);

    if (!IsSocketValid(sockFd)) {
        LogError("SendAll: Invalid socket file descriptor.");

        LogError("SendAll: Invalid socket file descriptor passed.");

        errno = EBADF;

        perror("SendAll");

        LogDebug("SendAll: Attempting to free socket mutex resources...");

        FreeSocketMutex();

        LogDebug("SendAll: Socket mutex resources freed.");

        LogDebug("SendAll: Done.");

        exit(ERROR);
    }

    LogInfo("SendAll: A valid socket file descriptor was passed.");

    LogInfo("SendAll: Checking whether the buffer of text to send is empty...");

    if (message == NULL || ((char*) message)[0] == '\0'
            || strlen((char*) message) == 0) {
        LogError("SendAll: Send buferr is empty.  This value is required.");

        errno = EINVAL;

        perror("SendAll");

        LogDebug("SendAll: Attempting to free socket mutex resources...");

        FreeSocketMutex();

        LogDebug("SendAll: Socket mutex resources freed.");

        LogDebug("SendAll: Done.");

        exit(ERROR);
    }

    LogInfo("SendAll: The send buffer is not empty.");

    char trimmed_message[strlen(message) + 1];
    Trim(trimmed_message, strlen(message) + 1, message);

    LogInfo("SendAll: message = '%s'", trimmed_message);

    LogInfo("SendAll: Checking whether the send buffer's size "
            "is a positive value...");

    LogInfo("SendAll: length = %d", (int) length);

    if ((int) length <= 0) {
        LogError("SendAll: Length should be a positive nonzero quanity.");

        errno = EINVAL;

        perror("SendAll");

        LogDebug("SendAll: Attempting to free socket mutex resources...");

        FreeSocketMutex();

        LogDebug("SendAll: Socket mutex resources freed.");

        LogDebug("SendAll: Done.");

        exit(ERROR);
    }

    char *ptr = (char*) message;

    int remaining = (int) length;

    LogInfo("SendAll: Starting send loop...");

    LogDebug("SendAll: total_bytes_sent = %d B", total_bytes_sent);

    LogDebug("SendAll: remaining = %d B", remaining);

    while (total_bytes_sent < remaining) {
        LogInfo("SendAll: Calling socket send function...");

        int bytes_sent = send(sockFd, ptr, length, 0);

        LogDebug("SendAll: bytes_sent = %d B", bytes_sent);

        if (bytes_sent < 1) {
            perror("SendAll");

            LogDebug("SendAll: Attempting to free socket mutex resources...");

            FreeSocketMutex();

            LogDebug("SendAll: Socket mutex resources freed.");

            LogDebug("SendAll: Done.");

            exit(ERROR);
        }

        LogDebug("SendAll: Updating counters...");

        total_bytes_sent += bytes_sent;

        ptr += bytes_sent;
        remaining -= bytes_sent;

        LogDebug("SendAll: total_bytes_sent = %d B", total_bytes_sent);

        LogDebug("SendAll: remaining = %d B", remaining);
    }

    LogDebug("SendAll: Sending complete.");

    LogDebug("SendAll: Socket mutex lock released.");

    LogInfo("SendAll: Result = %d B total sent.", total_bytes_sent);

    LogDebug("SendAll: Done.");

    return total_bytes_sent;
}

int Send(int sockFd, const char *buf) {
    LogDebug("In Send");

    LogInfo("Send: Checking whether we have been passed a valid socket file "
            "descriptor...");

    LogDebug("Send: sockFd = %d", sockFd);

    if (!IsSocketValid(sockFd)) {
        LogError("Send: Invalid socket file descriptor passed.");

        errno = EBADF;

        LogDebug("Send: errno set to %d", errno);

        LogDebug("Send: Done.");

        exit(ERROR);
    }

    LogInfo("Send: The socket file descriptor passed is valid.");

    LogInfo("Send: Checking whether text was passed in for sending...");

    if (IsNullOrWhiteSpace(buf)) {
        LogError("Send: Nothing was passed to us to send.  Stopping.");

        LogDebug("Send: Returning zero.");

        LogDebug("Send: Done.");

        // Nothing to send
        return 0;
    }

    LogInfo("Send: We were supplied with text for sending.");

    int buf_len = strlen(buf);

    LogInfo("Send: buf_len = %d", buf_len);

    LogInfo("Send: Now attempting the send operation...");

    int bytes_sent = SendAll(sockFd, buf, buf_len);

    LogInfo("Send: Sent %d bytes.", bytes_sent);

    if (bytes_sent < 0) {
        LogError("Send: Failed to send data.");

        error_and_close(sockFd, "Send: Failed to send data.");

        LogDebug("Send: Attempting to free socket mutex resources...");

        FreeSocketMutex();

        LogDebug("Send: Socket mutex resources freed.");

        LogDebug("Send: Done.");

        exit(ERROR);
    }

    LogInfo("Send: %d B sent.", bytes_sent);

    LogDebug("Send: Done.");

    return bytes_sent;
}

/**
 * @brief Connects a socket to a remote host whose hostname or IP address and
 * port number is specified.
 * @param sockFd Socket file descriptor representing a socket that is not yet
 * connected to a remote endpoint.
 * @param hostnameOrIp String indicating the human-readable (in DNS) hostname
 * or the IP address of the remote host.
 * @param port Port number that the service on the remote host is listening on.
 * @returns Zero if successful; ERROR if an error occurred.  The errno
 * value should be examined if this happens.  In other cases, this function
 * forcibly terminates the calling program with the ERROR exit code.
 */
int ConnectSocket(int sockFd, const char *hostnameOrIp, int port) {
    LogDebug("In ConnectSocket");

    int result = ERROR;

    LogDebug("ConnectSocket: sockFd = %d", sockFd);

    LogInfo("ConnectSocket: Checking for a valid socket file descriptor...");

    if (!IsSocketValid(sockFd)) {
        LogError("ConnectSocket: Attempted to connect to remote host "
                "with no endpoint.");
        exit(result);
    }

    LogInfo("ConnectSocket: A valid socket file descriptor was passed.");

    LogInfo("ConnectSocket: port = %d", port);

    LogInfo("ConnectSocket: Checking whether the port number used is valid...");

    if (!IsUserPortValid(port)) {
        if (stderr != GetErrorLogFileHandle()) {
            fprintf(stderr,
                    "ConnectSocket: An invalid value is being used for the "
                            "port number of the server.");
        }

        LogError("ConnectSocket: Port number must be in the range "
                "1024-49151 inclusive.");

        LogInfo("ConnectSocket: Attempting to close the socket...");

        CloseSocket(sockFd);

        LogInfo("ConnectSocket: Socket closed.");

        LogInfo("ConnectSocket: Attempting to release the socket mutex...");

        FreeSocketMutex();

        LogInfo("ConnectSocket: Resources for socket mutex have been freed.");

        LogDebug("ConnectSocket: Done.");

        exit(result);
    }

    LogInfo("ConnectSocket: The port number in use is valid.");

    struct hostent *he;						// Host entry
    struct sockaddr_in server_address; 		// Structure for the server
                                            // address and port

    LogInfo("ConnectSocket: Attempting to resolve the hostname or "
            "IP address '%s'...", hostnameOrIp);

    // First, try to resolve the host name or IP address passed to us,
    // to ensure that the host can even be found on the network in the first
    // place.  Calling the function below also has the added bonus of
    // filling in a hostent structure for us if it succeeds.
    if (!IsHostnameValid(hostnameOrIp, &he)) {
        LogError("ConnectSocket: Cannot connect to server on '%s'.",
                hostnameOrIp);

        if (GetErrorLogFileHandle() != stderr) {
            fprintf(stderr, "ConnectSocket: Cannot connect to server on '%s'.",
                    hostnameOrIp);
        }

        LogInfo("ConnectSocket: Attempting to close the socket...");

        CloseSocket(sockFd);

        LogInfo("ConnectSocket: Socket closed.");

        LogInfo("ConnectSocket: Attempting to release the socket mutex...");

        FreeSocketMutex();

        LogInfo("ConnectSocket: Resources for socket mutex have been freed.");

        LogDebug("ConnectSocket: Done.");

        exit(result);
    }

    LogInfo("ConnectSocket: The hostname or IP address passed could be "
            "resolved.");

    LogInfo("ConnectSocket: Obtaining a lock on the socket mutex...");

    LockSocketMutex();
    {
        LogInfo("ConnectSocket: Lock on socket mutex obtained, or it was "
                "not necessary.");

        LogInfo("ConnectSocket: Attempting to contact the server at '%s' "
                "on port %d...", hostnameOrIp, port);

        /* copy the network address to sockaddr_in structure */
        memcpy(&server_address.sin_addr, he->h_addr_list[0], he->h_length);
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(port);

        if ((result = connect(sockFd, (struct sockaddr*) &server_address,
                sizeof(server_address))) < 0) {
            LogError("ConnectSocket: The attempt to contact the "
                    "server at '%s' on port %d failed.", hostnameOrIp, port);

            LogInfo("ConnectSocket: Releasing the lock on the socket mutex...");

            UnlockSocketMutex();

            LogInfo("ConnectSocket: Socket mutex lock released.");

            LogInfo("ConnectSocket: Releasing operating system resources "
                    "consumed by the socket mutex...");

            FreeSocketMutex();

            LogInfo("ConnectSocket: Operating system resources consumed "
                    "by socket mutex freed.");

            CloseSocket(sockFd);

            /* If we are logging to a file and not the screen, print a message on the
             * screen for an interactive user that the connect operation failed. */
            if (GetLogFileHandle() != stdout) {
                fprintf(stdout, CONNECT_OPERATION_FAILED, hostnameOrIp, port);
            }

            CloseLogFileHandles();

            LogDebug("ConnectSocket: Done.");

            exit(ERROR);
        }

        LogInfo("ConnectSocket: Connected to the server at '%s' on port %d.",
                hostnameOrIp, port);

        LogInfo("ConnectSocket: Releasing the socket mutex...");
    }
    UnlockSocketMutex();

    LogInfo("ConnectSocket: The socket mutex has been released.");

    LogInfo("ConnectSocket: result = %d", result);

    LogDebug("ConnectSocket: Done.");

    return result;
}

void CloseSocket(int sockFd) {
    LogDebug("In CloseSocket");

    LogDebug("CloseSocket: sockFd = %d", sockFd);

    LogInfo("CloseSocket: Checking for a valid socket file descriptor...");

    if (!IsSocketValid(sockFd)) {
        LogError("CloseSocket: Valid socket file descriptor not passed.");

        return;	// just silently fail if the socket file descriptor passed is invalid
    }

    LogInfo("CloseSocket: A valid socket file descriptor was passed.");

    LogInfo("CloseSocket: Attempting to shut down the socket with"
            " file descriptor %d...", sockFd);

    if (OK != shutdown(sockFd, SHUT_RD)) {
        /* This is not really an error, since shutting down a socket
         * really just means disabling reads/writes on an open socket,
         * not closing it.  Who cares if we cannot perform this
         * operation? */

        LogWarning("CloseSocket: Failed to shut down the socket with file "
                "descriptor %d.", sockFd);
    } else {
        LogInfo("CloseSocket: Socket shut down successfully.");
    }

    LogInfo("CloseSocket: Attempting to close the socket...");

    int retval = close(sockFd);

    if (retval < 0) {
        LogError("CloseSocket: Failed to close the socket.");

        LogDebug("CloseSocket: Done.");

        return;
    }

    LogInfo("CloseSocket: Socket closed successfully.");

    LogDebug("CloseSocket: Done.");
}
