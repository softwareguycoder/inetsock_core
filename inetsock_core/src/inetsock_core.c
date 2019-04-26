///////////////////////////////////////////////////////////////////////////////
// inetsock_core.c: Implementations for the functions in this shared library

#include "stdafx.h"
#include "inetsock_core.h"

#include "socket_mutex.h"

#define CONNECT_OPERATION_FAILED "connect: Failed to contact server on " \
                                 "'%s' and port %d.\n"

pthread_mutex_t* g_pSocketMutex; /* mutex for socket access */

///////////////////////////////////////////////////////////////////////////////
// AcceptSocket function

int AcceptSocket(int nSocket, struct sockaddr_in *pAddrInfo) {

    int nClientSocket = ERROR;

    if (!IsSocketValid(nSocket)) {
        errno = EBADF;

        perror("AcceptSocket");

        FreeSocketMutex();

        exit(ERROR);
    }

    if (pAddrInfo == NULL) {
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
    socklen_t clientAddressLength = sizeof(*pAddrInfo);

    if ((nClientSocket = accept(nSocket, (struct sockaddr*) pAddrInfo,
            &clientAddressLength)) < 0) {
        if (EBADF != errno && EINVAL != errno) {
            perror("AcceptSocket");

            FreeSocketMutex();

            CloseSocket(nSocket);
        }

        /* If errno is EBADF, this is just from a thread being terminated
         * outside of this accept() call. In this case, merely return an
         * invalid socket file descriptor value instead of forcibly
         * terminating the program.  If errno is anything else
         * besides EBADF, then forcibly exit. */

        if (EBADF == errno || EINVAL == errno) {
            return ERROR;
        } else {
            exit(ERROR);
        }
    }

    return nClientSocket;
}

///////////////////////////////////////////////////////////////////////////////
// BindSocket function

int BindSocket(int nSocket, struct sockaddr_in *pAddrInfo) {
    int nResult = ERROR;

    if (!IsSocketValid(nSocket)) {
        errno = EBADF;

        perror("BindSocket");

        FreeSocketMutex();

        exit(ERROR);
    }

    LockSocketMutex();
    {
        if (pAddrInfo == NULL) {
            errno = EINVAL; // addr param required

            perror("BindSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        nResult = bind(nSocket, (struct sockaddr*) pAddrInfo,
                sizeof(*pAddrInfo));
        if (nResult < 0) {
            perror("BindSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }
    }
    UnlockSocketMutex();

    return nResult;
}

///////////////////////////////////////////////////////////////////////////////
// CloseSocket function

void CloseSocket(int nSocket) {
    if (!IsSocketValid(nSocket)) {
        return; // just silently fail if the socket file descriptor
                // passed is invalid
    }

    if (OK != shutdown(nSocket, SHUT_RD)) {
        /* This is not really an error, since shutting down a socket
         * really just means disabling reads/writes on an open socket,
         * not closing it.  Who cares if we cannot perform this
         * operation? */

        LogWarning("CloseSocket: Failed to shut down the socket with file "
                "descriptor %d.", nSocket);
    }

    int nResult = close(nSocket);

    if (nResult < 0) {
        return;
    }
}

///////////////////////////////////////////////////////////////////////////////
// ConnectSocket function -- connects a client to a server.

int ConnectSocket(int nSocket, const char *pszHostName, int nPort) {
    int result = ERROR;

    if (!IsSocketValid(nSocket)) {
        exit(result);
    }

    if (!IsUserPortNumberValid(nPort)) {
        if (stderr != GetErrorLogFileHandle()) {
            fprintf(stderr,
                    "ConnectSocket: An invalid value is being used for the "
                            "port number of the server.\n");
        }

        CloseSocket(nSocket);

        FreeSocketMutex();

        exit(result);
    }

    struct sockaddr_in serverAddress;       // Structure for the server
                                            // address and port

    struct hostent *pHostEntry = NULL;

    // First, try to resolve the host name or IP address passed to us,
    // to ensure that the host can even be found on the network in the first
    // place.  Calling the function below also has the added bonus of
    // filling in a hostent structure for us if it succeeds.
    if (!IsHostnameValidEx(pszHostName, &pHostEntry)) {
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
        memcpy(&serverAddress.sin_addr, pHostEntry->h_addr_list[0],
                pHostEntry->h_length);
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(nPort);

        if ((result = connect(nSocket, (struct sockaddr*) &serverAddress,
                sizeof(serverAddress))) < 0) {
            UnlockSocketMutex();

            FreeSocketMutex();

            CloseSocket(nSocket);

            /* If we are logging to a file and not the screen, print a
             * message on the screen for an interactive user that the connect
             * operation failed. */
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

///////////////////////////////////////////////////////////////////////////////
// CreateSocket function

int CreateSocket() {
    int nSocket = INVALID_SOCKET_HANDLE;

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

///////////////////////////////////////////////////////////////////////////////
// CreateSocketMutex function - Allocates operating system resources for the
// socket mutex handle.
//

// We are not using the corresponding CreateMutex function from the
// mutex_core library since the concern is that not every client of THIS library
// will necessarily want to do all socket communications in a critical section;
// therefore we want to not add unnecessary dependencies.
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
// ErrorAndClose function

void ErrorAndClose(int nSocket, const char *pszErrorMessage) {
    if (IsNullOrWhiteSpace(pszErrorMessage)) {
        perror(NULL);
        exit(ERROR);
        return;   // This return statement might not fire, but just in case.
    }

    LogError(pszErrorMessage);

    perror(NULL);

    if (nSocket > 0) {
        close(nSocket);
        fprintf(stderr, "Exiting with error code %d.", ERROR);
    }

    exit(ERROR);
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

///////////////////////////////////////////////////////////////////////////////
// GetServerAddrInfo function

void GetServerAddrInfo(int nPort, struct sockaddr_in *pAddrInfo) {
    if (!IsUserPortNumberValid(nPort)) {
        FreeSocketMutex();

        exit(ERROR);
    }

    LockSocketMutex();
    {
        if (pAddrInfo == NULL) {
            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }

        // Populate the fields of the sockaddr_in structure passed to us
        // with the proper values.
        pAddrInfo->sin_family = AF_INET;
        pAddrInfo->sin_port = htons(nPort);
        pAddrInfo->sin_addr.s_addr = htons(INADDR_ANY);
    }
    UnlockSocketMutex();
}

///////////////////////////////////////////////////////////////////////////////
// IsHostnameValid function

int IsHostnameValid(const char *pszHostName) {
    struct hostent *pHostEntry;             // Host entry

    return IsHostnameValidEx(pszHostName, &pHostEntry);
}

///////////////////////////////////////////////////////////////////////////////
// IsHostnameValidEx function

int IsHostnameValidEx(const char *pszHostName, struct hostent** ppHostEntry) {
    if (IsNullOrWhiteSpace(pszHostName)) {
        // The hostnameOrIP parameter cannot be blank, since we need to find
        // out if the hostname or IP supplied is valid.  Can't very well do that
        // for a blank value!
        return FALSE;
    }

    if (ppHostEntry == NULL) {
        return FALSE;
    }

    LockSocketMutex();
    {
        if ((*ppHostEntry = gethostbyname(pszHostName)) == NULL) {
            *ppHostEntry = NULL;

            UnlockSocketMutex();

            // return FALSE if no storage location for the 'he' pointer passed
            return FALSE;
        }
    }
    UnlockSocketMutex();

    return TRUE;

}
///////////////////////////////////////////////////////////////////////////////
// IsUserPortNumberValid function

int IsUserPortNumberValid(int nPort) {
    return nPort >= 1024 && nPort < 49151;
}

///////////////////////////////////////////////////////////////////////////////
// IsSocketValid function

int IsSocketValid(int nSocket) {
    /* Linux socket file descriptors are always positive, nonzero
     * integers when they represent a valid socket handle.
     */
    if (nSocket <= 0) {
        return FALSE;
    }

    return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// ListenSocket function

int ListenSocket(int nSocket) {
    int nResult = ERROR;

    if (!IsSocketValid(nSocket)) {
        errno = EBADF;

        perror("ListenSocket");

        FreeSocketMutex();

        exit(ERROR);
    }

    LockSocketMutex();
    {
        nResult = listen(nSocket, BACKLOG_SIZE);

        if (nResult < 0) {
            perror("ListenSocket");

            UnlockSocketMutex();

            FreeSocketMutex();

            exit(ERROR);
        }
    }
    UnlockSocketMutex();

    return nResult;
}

///////////////////////////////////////////////////////////////////////////////
// LockSocketMutex function -- for internal use by this code only.

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

///////////////////////////////////////////////////////////////////////////////
// Receive function - receives data from a TCP socket.

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

    int nBytesRead = 0;

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
        char ch;        // receive one char at a time until a newline is found
        nBytesRead = recv(nSocket, &ch, RECV_BLOCK_SIZE, RECV_FLAGS);
        if (nBytesRead < 0) {
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
        nTotalBytesRead += nBytesRead;

        // If the newline ('\n') character was the char received,
        // then we're done; it's time to apply the null terminator.
        if (ch == '\n') {
            break;
        }

        // re-allocate more memory and make sure to leave room
        // for the null-terminator.

        int nNewReceiveBufferSize = (nTotalBytesRead + RECV_BLOCK_SIZE + 1)
                * sizeof(char);

        *ppszReceiveBuffer = (char*) realloc(*ppszReceiveBuffer,
                nNewReceiveBufferSize);
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

        FreeBuffer((void**) ppszReceiveBuffer);

        return 0;
    }

    // Now the storage at address *buf should contain the entire
    // line just received, plus the newline and the null-terminator, plus
    // any previously-received data
    return nTotalBytesRead;
}

///////////////////////////////////////////////////////////////////////////////
// Send function

int Send(int nSocket, const char *pszMessage) {
    if (!IsSocketValid(nSocket)) {
        fprintf(stderr, "Send: Invalid socket handle.\n");
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
        ErrorAndClose(nSocket, "Send: Failed to send data.\n");

        FreeSocketMutex();

        exit(ERROR);
    }

    //fprintf(stdout, "%d B sent.\n", bytes_sent);

    //fprintf(stdout, "Send: Done\n");

    return bytes_sent;
}

///////////////////////////////////////////////////////////////////////////////
// SendAll function

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

    if ((int) nLength <= 0) {
        errno = EINVAL;

        perror("SendAll");

        FreeSocketMutex();

        exit(ERROR);
    }

    char *ptr = (char*) pszMessage;

    int nBytesRemaining = (int) nLength;

    while (nTotalBytesSent < nBytesRemaining) {
        int nBytesSent = send(nSocket, ptr, nLength, MSG_NOSIGNAL);

        if (nBytesSent < 1) {
            perror("SendAll");

            CloseSocket(nSocket);

            FreeSocketMutex();

            exit(ERROR);
        }

        nTotalBytesSent += nBytesSent;

        ptr += nBytesSent;
        nBytesRemaining -= nBytesSent;
    }

    return nTotalBytesSent;
}

///////////////////////////////////////////////////////////////////////////////
// SetSocketNonBlocking function

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

///////////////////////////////////////////////////////////////////////////////
//SetSocketReusable function

int SetSocketReusable(int nSocket) {
    int nResult = ERROR;

    if (!IsSocketValid(nSocket)) {

        return nResult;
    }

    // Set socket options to allow the socket to be reused.
    LockSocketMutex();
    {
        nResult = setsockopt(nSocket, SOL_SOCKET, SO_REUSEADDR, &(int ) {
                    1 }, sizeof(int));
        if (nResult < 0) {
            perror("setsockopt");

            UnlockSocketMutex();

            return nResult;
        }
    }
    UnlockSocketMutex();

    return nResult;
}

///////////////////////////////////////////////////////////////////////////////
// UnlockSocketMutex function -- internal function for use by this library
// only

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

