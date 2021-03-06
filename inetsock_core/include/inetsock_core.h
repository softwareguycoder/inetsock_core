#ifndef __INETSOCK_CORE_H__
#define __INETSOCK_CORE_H__

#include "stdafx.h"

#include <../../common_core/common_core/include/common_core.h>

#define RECV_BLOCK_SIZE	1
#define RECV_FLAGS		0
#define BACKLOG_SIZE	128		// Max number of client connections
#define INVALID_SOCKET_VALUE -1

typedef int (*LPRECEIVE_DATA_HANDLER)(char**);

typedef int (*LPRECEIVE_DATA_HANDLER2)(void*, char**);

typedef void (*LPRECEIVE_LINE_PROCESSOR)(const char*, int);

typedef void (*LPRECEIVE_LINE_PROCESSOR2)(void*, const char*, int);

typedef BOOL (*LPRECEIVE_TERM_PREDICATE)(const char*);

typedef BOOL (*LPRECEIVE_TERM_PREDICATE2)(void*, const char*);

/**
 * @brief Accepts an incoming connection on a socket and returns information
 * about the remote host.
 * @param nSocket Socket file descriptor on which to accept new incoming
 * connections.
 * @param pAddrInfo Reference to a sockaddr_in structure that receives info
 * aboutthe IP address of the remote endpoint.
 * @returns Socket file descriptor representing the local endpoint of the new
 * incoming connection; or a negative number indicating that errno should be
 * read for the error description.
 * @remarks Returns ERROR if any of the following are true: (a) sets errno
 * to EBADF if nSocket is an invalid value (nonpositive) or (b) sets errno to
 * EINVAL if addr is NULL. This function blocks the calling thread until an
 * incoming connection has been  established.
 */
int AcceptSocket(int nSocket, struct sockaddr_in *pAddrInfo);

/**
 * @brief Binds a server socket to the address and port specified by the 'addr'
 * parameter.
 * @param nSocket Socket file descriptor that references the socket to be bound.
 * @param pAddrInfo Pointer to a sockaddr_in structure that specifies the host
 * and port to which the socket endpoint should be bound.
 */
int BindSocket(int nSocket, struct sockaddr_in *pAddrInfo);

/**
 * @brief Attempts to release operating system resources that are allocated to
 * the specified socket.
 * @param nSocket Socket file descriptor referring to the socket that is to be
 * closed.
 */
void CloseSocket(int nSocket);

/**
 * @brief Connects a socket to a remote host whose hostname or IP address and
 * port number is specified.
 * @param nSocket Socket file descriptor representing a socket that is not yet
 * connected to a remote endpoint.
 * @param hostnameOrIp String indicating the human-readable (in DNS) hostname
 * or the IP address of the remote host.
 * @param port Port number that the service on the remote host is listening on.
 * @returns Zero if successful; ERROR if an error occurred.  The errno
 * value should be examined if this happens.  In other cases, this function
 * forcibly terminates the calling program with the ERROR exit code.
 */
int ConnectSocket(int nSocket, const char *hostnameOrIp, int port);

/**
 *  @brief Creates a new socket endpoint for communicating with a remote
 *  host over TCP/IP.
 *  @returns Socket file descriptor which provides a handle to the newly-
 *  created socket endpoint.
 *  @remarks If an error occurs, prints the error to the console and forces
 *  the program to exit with the ERROR exit code.
 */
int CreateSocket();

/**
 * @brief Initializes the global socket mutex handle.
 * @remarks The global socket mutex handle is used to ensure
 * communications are handled in as atomic and thread-safe
 * manner as possible.  This function is to be called once per
 * application, preferably from the main function. */
void CreateSocketMutex();

/**
 *  @brief Reports the error message specified as well as the error from
 *  the system.  Closes the socket file descriptor provided in order to
 *   free operating system resources.  Exits the program with the ERROR exit
 *   code.
 *  @param nSocket Socket file descriptor to be closed after the error
 *  has been reported.
 *  @param pszErrorMessage Additional error text to be echoed to the console.
 **/
void ErrorAndClose(int nSocket, const char *pszErrorMessage);

/**
 * @brief Releases resources used by the global socket mutex handle.
 * @remarks The global socket mutex handle is used to ensure
 * communications are handled in as atomic and thread-safe
 * manner as possible.  This function is to be called once
 * per application, preferably from the main function. */
void FreeSocketMutex();

/**
 * @name GetLineCharCount
 * @brief Gets the count of characters in a line, excluding the terminating
 * <LF>.
 * @param pszLine Line to count characters for.
 * @return Count of characters in the line provided, or zero if the string
 * only contains whitespace or is of zero length.
 */
int GetLineCharCount(const char* pszLine);

/**
 * @brief Populates the port and address information for a server
 * so the server knows the hostname/IP address and port of the computer
 * it is listening on.
 * @param pszPort String containing the port number to listen on.  Must be
 * numeric.
 * @param pAddrInfo Address of storage that will receive a filled-in sockaddr_in
 * structure that defines the server endpoint.
 * @remarks If invalid input is supplied or an error occurs, reports
 * these problems to the console and forces the program to die with the
 * ERROR exit code.
 */
void GetServerAddrInfo(int nPort, struct sockaddr_in *pAddrInfo);

/**
 * @brief Attempts to resolve the hostname or IP address provided with
 * the Domain Name System (DNS) and reports success or failure.
 * @param pszHostName The hostname or IP address of the remote computer
 * that is to be resolved with DNS.
 * @returns Zero if resolution has failed; nonzero otherwise.
 * @remarks If this function returns nonzero, then the value of '*he'
 *  will be the address of a storage location containing a hostent
 *  structure containing information for the remote host.
 */
int IsHostnameValid(const char *pszHostName);

/**
 * @brief Attempts to resolve the hostname or IP address provided with
 * the Domain Name System (DNS) and reports success or failure.
 * @param pszHostName The hostname or IP address of the remote computer
 * that is to be resolved with DNS.
 * @param ppHostEntry Address of a hostent structure to be filled by the
 * gethostbyname function.
 * @returns Zero if resolution has failed; nonzero otherwise.
 * @remarks If this function returns nonzero, then the value of '*he'
 *  will be the address of a storage location containing a hostent
 *  structure containing information for the remote host.
 */
int IsHostnameValidEx(const char *pszHostName, struct hostent** ppHostEntry);

/**
 * \brief Checks the integer value supplied to ensure it's a valid user port
 * number and not reserved for a different service.
 * \param port Variable containing the value to be validated.
 * \returns Zero if the 'port' parameter is not in the range [1024, 49151]
 * (inclusive); nonzero otherwise.
 */
int IsUserPortNumberValid(int port);

/**
 * @brief Determines whether the socket file descriptor passed is valid.
 * @param nSocket An integer specifying the value of the file descriptor to be
 * checked.
 * @returns TRUE if the descriptor is valid; FALSE otherwise.
 * @remarks "Valid" in this context simply means a positive integer.  This
 * function's job is not to tell you whether the socket is currently open
 * or closed.
 */
int IsSocketValid(int nSocket);

/**
 * @brief Sets up a TCP or UDP server socket to listen on a port and IP address
 * to which it has been bound previously with the SocketDemoUtils_bind function.
 * @param nSocket Socket file descriptor.
 * @returns ERROR if the socket file descriptor passed in nSocket does not
 * represent a valid, open socket and sets errno to EBADF.  Otherwise, returns
 *  the result of
 * calling listen on the socket file descriptor passed with a backlog size of
 * BACKLOG_SIZE (128 by default).  Zero is returned if the operation was
 * successful.
 */
int ListenSocket(int nSocket);

/**
 * @brief Processes multiline input over a socket using a trio of function
 * pointers.
 * @param lpfnDataHandler Address of a function that is called to execute a
 * receive operation on the socket.  This may vary from implementation to
 * implementation.
 * @param lpfnLineProcessor Address of a function that is called to process
 * each line of data as it comes in.
 * @param lpfnTermPredicate Address of a function that examines the currently-
 * received content and decides whether the end of the content has been
 * reached.
 * @remarks Call this function to run a synchronous receive loop to recieve
 * lines over a socket.  Since what constitutes a line, what is done with the
 * current line, and when the content ends is all implementation-specifics,
 * applications must provide callbacks conforming to the signatures given
 * in this function's prototype.
 */
void ReceiveMultilineData(
    LPRECEIVE_DATA_HANDLER lpfnDataHandler,
    LPRECEIVE_LINE_PROCESSOR lpfnLineProcessor,
    LPRECEIVE_TERM_PREDICATE lpfnTermPredicate);

/**
 * @brief Processes multiline input over a socket using a trio of function
 * pointers.
 * @param pvUserState Pointer to a block of memory containing user state that
 * is to be passed to the callbacks.
 * @param lpfnDataHandler2 Address of a function that is called to execute a
 * receive operation on the socket.  This may vary from implementation to
 * implementation. The callback must accept pvUserState as its first argument.
 * @param lpfnLineProcessor2 Address of a function that is called to process
 * each line of data as it comes in.  The callback must also accept
 * pvUserState as its first argument.
 * @param lpfnTermPredicate2 Address of a function that examines the currently-
 * received content and decides whether the end of the content has been
 * reached. The callback must also accept pvUserState as its first argument.
 * @remarks Call this function to run a synchronous receive loop to recieve
 * lines over a socket.  Since what constitutes a line, what is done with the
 * current line, and when the content ends is all implementation-specifics,
 * applications must provide callbacks conforming to the signatures given
 * in this function's prototype.
 */
void ReceiveMultilineData2(
    void* pvUserState,
    LPRECEIVE_DATA_HANDLER2 lpfnDataHandler2,
    LPRECEIVE_LINE_PROCESSOR2 lpfnLineProcessor2,
    LPRECEIVE_TERM_PREDICATE2 lpfnTermPredicate2);

/**
 * @brief Reads a line of data, terminated by the '\n' character, from a socket.
 * @param nSocket Socket file descriptor from which to receive data.
 * @param ppszReceiveBuffer Reference to an address at which to allocate storage
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
int Receive(int nSocket, char **ppszReceiveBuffer);

/**
 *	@brief Sends data to the endpoint on the other end of the connection
 *	referenced by the specified connected socket.
 *	@param nSocket Socket file descriptor.  Must be a descriptor for a valid
 *	socket that is currently connected to a remote host.
 *	@param pszMessage Address of a character array containing the bytes to be
 *	sent.
 *	@returns ERROR if the operation failed; number of bytes sent otherwise.
 *	If the ERROR value is returned, errno should be examined to determine the
 *  cause of the error.
 */
int Send(int nSocket, const char *pszMessage);

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
int SendAll(int nSocket, const char *pszMessage, size_t nLength);

/**
 * @brief Sets preferences on the socket specified to make it non-blocking.
 * @param nSocket Socket file descriptor to perform the operation on.
 */
void SetSocketNonBlocking(int nSocket);

/**
 * @brief Makes the socket passed to it reusable by setting socket options.
 * @param nSocket Positive integer specifying the Linux file descriptor of the
 * socket to mark.
 * @returns Zero if the operation succeeded; ERROR otherwise.  errno contains
 * the error.
 */
int SetSocketReusable(int nSocket);

/**
 * @brief Raises an error message on a socket send all failure, and shuts
 * down the calling applciation after releasing operating system resources.
 * @param pszMessage The data you are attempting to send.
 * @param nSocket Socket file descriptor of the socket over which the
 * send operation was being attempted.
 */
void ThrowSendAllFailedException(const char *pszMessage, int nSocket);

#endif //__INETSOCK_CORE_H__
