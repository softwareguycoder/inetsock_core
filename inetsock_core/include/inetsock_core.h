#ifndef __INETSOCK_CORE_H__
#define __INETSOCK_CORE_H__

#include "stdafx.h"
#include "utils.h"

#include <../../common_core/common_core/include/common_core.h>

#define RECV_BLOCK_SIZE	1
#define RECV_FLAGS		0
#define BACKLOG_SIZE	128		// Max number of client connections

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
void GetServerAddrInfo(const char *pszPort, struct sockaddr_in *pAddrInfo);

/**
 *  @brief Reports the error message specified as well as the error from
 *  the system. Exits the program with the ERROR exit code.
 *  @param pszErrorMessage Additional error text to be echoed to the console.
 **/
void HandleError(const char* pszErrorMessage);

/**
 * @brief Attempts to resolve the hostname or IP address provided with
 * the Domain Name System (DNS) and reports success or failure.
 * @param pszHostName The hostname or IP address of the remote computer
 * that is to be resolved with DNS.
 * @param ppHostEntry Address of a storage location that is to be filled with a
 * hostent structure upon successful resolution of the hostname or
 * IP address provided.
 * @returns Zero if resolution has failed; nonzero otherwise.
 * @remarks If this function returns nonzero, then the value of '*he'
 *  will be the address of a storage location containing a hostent
 *  structure containing information for the remote host.
 */
int IsHostnameValid(const char *pszHostName, struct hostent **ppHostEntry);

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

#endif //__INETSOCK_CORE_H__
