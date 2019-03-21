///////////////////////////////////////////////////////////////////////////////
// socketapi.c: Definitions for the functions in the SocketDemoUtils.lib
// shared library

#include <inetsock_core.h>
#include "stdafx.h"

/**
 * \brief Attempts to resolve the hostname or IP address provided with
 * the Domain Name System (DNS) and reports success or failure.
 * \param hostnameOrIP The hostname or IP address of the remote computer
 * that is to be resolved with DNS.
 * \param Address of a storage location that is to be filled with a 
 *  hostent structure upon successful resolution of the hostname or 
 *  IP address provided.  
 * \returns Zero if resolution has failed; nonzero otherwise.
 * \remarks If this function returns nonzero, then the value of '*he'
 *  will be the address of a storage location containing a hostent
 *  structure containing information for the remote host.
 */
int isValidHostnameOrIp(const char *hostnameOrIP, struct hostent **he) {
	log_debug("In isValidHostnameOrIp");

	log_debug("hostnameOrIP: hostnameOrIP = %s", hostnameOrIP);

	log_info(
			"isValidHostnameOrIp: Checking whether the 'hostnameOrIP' parameter is blank...");

	if (hostnameOrIP == NULL || hostnameOrIP[0] == '\0'
			|| strlen(hostnameOrIP) == 0) {
		log_error("hostnameOrIP parameter is blank.");

		log_debug("isValidHostnameOrIp: Returning FALSE.");

		log_debug("isValidHostnameOrIp: Done.");

		return FALSE;
	}

	log_info("isValidHostnameOrIp: The 'hostnameOrIP' parameter has a value.");

	log_info(
			"isValidHostnameOrIp: Checking whether the 'he' parameter has a value...");

	if (he == NULL) {

		log_error(
				"isValidHostnameOrIp: The 'he' parameter has a null reference.");

		log_debug("isValidHostnameOrIp: Returning FALSE.");

		log_debug("isValidHostnameOrIp: Done.");

		// return FALSE if no storage location for the 'he' pointer passed
		return FALSE;
	}

	log_info("isValidHostnameOrIp: The 'he' parameter has a value.");

	log_info("isValidHostnameOrIp: Resolving host name or IP address '%s'...",
			hostnameOrIP);

	if ((*he = gethostbyname(hostnameOrIP)) == NULL) {
		log_error(
				"isValidHostnameOrIp: Hostname or IP address resolution failed.");

		*he = NULL;

		log_info("isValidHostnameOrIp: 'he' parameter set to NULL.");

		log_debug("isValidHostnameOrIp: Returning FALSE.");

		log_debug("isValidHostnameOrIp: Done.");

		// return FALSE if no storage location for the 'he' pointer passed
		return FALSE;
	}

	log_info(
			"isValidHostnameOrIp: Hostname or IP address resolution succeeded.");

	log_debug("isValidHostnameOrIp: Done.");

	return TRUE;
}

/**
 * \brief Frees the memory at the address specified.
 * \param ppBuffer Address of a pointer which points to memory
 * allocated with the '*alloc' functions (malloc, calloc, realloc).
 * \remarks Remember to cast the address of the pointer being passed 
 * to this function to void** 
 */
void free_buffer(void **ppBuffer) {
	log_debug("In free_buffer");

	log_info("free_buffer: Checking pointer provided...");

	if (ppBuffer == NULL || *ppBuffer == NULL) {
		log_warning(
				"free_buffer: No memory has been passed to work on.  Nothing to do.");

		log_debug("free_buffer: Done.");

		return;     // Nothing to do since there is no address referenced
	}

	log_info(
			"free_buffer: Freeing the memory referenced by the ppBuffer parameter...");

	free(*ppBuffer);
	*ppBuffer = NULL;

	log_debug("free_buffer: Done.");
}

/**
 *  \brief Reports the error message specified as well as the error from
 *  the system.  Closes the socket file descriptor provided in order to 
 *   free operating system resources.  Exits the program with the ERROR exit
 *   code.
 *  \param sockFd Socket file descriptor to be closed after the error
 *  has been reported.
 *  \param msg Additional error text to be echoed to the console.
 **/
void error_and_close(int sockFd, const char *msg) {
	if (msg == NULL || strlen(msg) == 0 || msg[0] == '\0') {
		perror(NULL);
		exit(ERROR);
		return;       // This return statement might not fire, but just in case.
	}

	log_error(msg);
	perror(NULL);

	if (sockFd > 0) {
		close(sockFd);
		fprintf(stderr, "Exiting with error code %d.", ERROR);
	}

	exit(ERROR);
}

/**
 *  \brief Reports the error message specified as well as the error from
 *  the system. Exits the program with the ERROR exit code.
 *  \param msg Additional error text to be echoed to the console.
 **/
void error(const char* msg) {
	if (msg == NULL || strlen(msg) == 0 || msg[0] == '\0') {
		return;
	}

	log_error(msg);
	perror(NULL);
	exit(ERROR);
}

/**
 *  \brief Creates a new socket endpoint for communicating with a remote
 *  host over TCP/IP.
 *  \returns Socket file descriptor which provides a handle to the newly-
 *  created socket endpoint. 
 *  \remarks If an error occurs, prints the error to the console and forces
 *  the program to exit with the ERROR exit code.
 */
int SocketDemoUtils_createTcpSocket() {
	log_debug("In SocketDemoUtils_createTcpSocket");

	log_info("SocketDemoUtils_createTcpSocket: Allocating new TCP endpoint...");

	int sockFd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockFd <= 0) {
		log_error("SocketDemoUtils_createTcpSocket: Could not create endpoint.");

		log_debug("SocketDemoUtils_createTcpSocket: Done.");

		exit(ERROR);
	}

	log_info("SocketDemoUtils_createTcpSocket: Endpoint created successfully.");

	log_info("SocketDemoUtils_createTcpSocket: Attempting to mark endpoint as reusable...");

	SocketDemoUtils_setSocketReusable(sockFd);

	log_info("SocketDemoUtils_createTcpSocket: Endpoint configured to be reusable.");

	log_info("SocketDemoUtils_createTcpSocket: sockFd = %d", sockFd);

	log_debug("SocketDemoUtils_createTcpSocket: Done.");

	return sockFd;
}

int SocketDemoUtils_setSocketReusable(int sockFd) {
	log_debug("In SocketDemoUtils_setSocketReusable");

	int retval = ERROR;

	log_info("SocketDemoUtils_setSocketReusable: Checking whether a valid socket file descriptor was passed...");

	if (sockFd <= 0) {
		log_error("SocketDemoUtils_setSocketReusable: The socket file descriptor has an invalid value.");

		log_debug("SocketDemoUtils_setSocketReusable: Done.");

		return retval;
	}

	log_info("SocketDemoUtils_setSocketReusable: A valid socket file descriptor has been passed.");

	log_info("SocketDemoUtils_setSocketReusable: Attempting to set the socket as reusable...");

	// Set socket options to allow the socket to be reused.
	retval = setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &(int ) { 1 }, sizeof(int));
	if (retval < 0) {
		log_error("SocketDemoUtils_setSocketReusable: Failed to mark socket as reusable.");

		log_debug("SocketDemoUtils_setSocketReusable: Done.");

		return retval;
	}

	log_debug("SocketDemoUtils_setSocketReusable: retval = %d", retval);

	log_debug("SocketDemoUtils_setSocketReusable: Done.");

	return retval;
}

/**
 *  \brief Populates the port and address information for a server
 *  so the server knows the hostname/IP address and port of the computer 
 *  it is listening on.
 *  \param port String containing the port number to listen on.  Must be numeric.
 *  \param hostnameOrIp String containing the hostname or IP address of the server
 *  computer.  Can be NULL, in which case, htons(INADDR_ANY) will be set.  Use NULL
 *  for a sevrer, and a specific value for a client.
 *  \param addr Address of storage that will receive a filled-in sockaddr_in structure
 *  that defines the server endpoint.
 *  \remarks If invalid input is supplied or an error occurs, reports thse problem
 *  to the console and forces the program to die with the ERROR exit code.
 */
void SocketDemoUtils_populateServerAddrInfo(const char *port,
		struct sockaddr_in *addr) {

	log_info("In SocketDemoUtils_populateServerAddrInfo");

	if (port == NULL || strlen(port) == 0 || port[0] == '\0') {
		log_error(
				"SocketDemoUtils_populateServerAddrInfo: String containing the port number is blank.");

		log_debug("SocketDemoUtils_populateServerAddrInfo: Done.");

		exit(ERROR);
	}

	if (addr == NULL) {
		log_error(
				"SocketDemoUtils_populateServerAddrInfo: Missing pointer to a sockaddr_in structure.");

		log_debug("SocketDemoUtils_populateServerAddrInfo: Done.");

		exit(ERROR);
	}

	// Get the port number from its string representation and then validate that it is in
	// the proper range
	int portnum = 0;
	int result = char_to_long(port, (long*) &portnum);
	if (result >= 0 && !isUserPortValid(portnum)) {
		log_error(
				"SocketDemoUtils_populateServerAddrInfo: Port number must be in the range 1024-49151 inclusive.");

		log_debug("SocketDemoUtils_populateServerAddrInfo: Done.");

		exit(ERROR);
	}

	// Populate the fields of the sockaddr_in structure passed to us with the proper values.

	log_info(
			"SocketDemoUtils_populateServerAddrInfo: Configuring server address and port...");

	addr->sin_family = AF_INET;
	addr->sin_port = htons(portnum);
	addr->sin_addr.s_addr = htons(INADDR_ANY);

	log_info(
			"SocketDemoUtils_populateServerAddrInfo: Server configured to listen on port %d.",
			portnum);

	log_debug("SocketDemoUtils_populateServerAddrInfo: Done.");
}

/**
 *  \brief Binds a server socket to the address and port specified by the 'addr'
 *   parameter.
 *  \param sockFd Socket file descriptor that references the socket to be bound.
 *  \param addr Pointer to a sockaddr_in structure that specifies the host and port
 *  to which the socket endpoint should be bound.
 */
int SocketDemoUtils_bind(int sockFd, struct sockaddr_in *addr) {
	log_debug("In SocketDemoUtils_bind");

	log_debug("SocketDemoUtils_bind: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_bind: Checking whether a valid socket file descriptor was passed...");

	if (sockFd <= 0) {
		log_error(
				"SocketDemoUtils_bind: Invalid socket file descriptor passed.");

		errno = EBADF;

		log_debug("SocketDemoUtils_bind: Set errno = %d", errno);

		log_debug("SocketDemoUtils_bind: Done.");

		return ERROR;   // Invalid socket file descriptor
	}

	log_info(
			"SocketDemoUtils_bind: A valid socket file descriptor has been passed.");

	log_info(
			"SocketDemoUtils_bind: Checking whether a valid sockaddr_in reference has been passed...");

	if (addr == NULL) {
		log_error(
				"SocketDemoUtils_bind: A null reference has been passed for the 'addr' parameter.  Nothing to do.");

		errno = EINVAL; // addr param required

		log_debug("SocketDemoUtils_bind: Set errno = %d", errno);

		log_debug("SocketDemoUtils_bind: Done.");

		return ERROR;
	}

	log_info(
			"SocketDemoUtils_bind: Attempting to bind socket %d to the server address...",
			sockFd);

	int retval = bind(sockFd, (struct sockaddr*) addr, sizeof(*addr));

	log_debug("SocketDemoUtils_bind: retval = %d", retval);

	if (retval < 0) {
		log_error("SocketDemoUtils_bind: Failed to bind socket.");

		log_debug("SocketDemoUtils_bind: errno = %d", errno);

		log_debug("SocketDemoUtils_bind: Done.");

		return ERROR;
	}

	log_info("SocketDemoUtils_bind: Successfully bound the server socket.");

	log_info("SocketDemoUtils_bind: Returning %d", retval);

	log_debug("SocketDemoUtils_bind: Done.");

	return retval;
}

/**
 * \brief Sets up a TCP or UDP server socket to listen on a port and IP address
 * to which it has been bound previously with the SocketDemoUtils_bind function.
 * \params sockFd Socket file descriptor.
 * \returns ERROR if the socket file descriptor passed in sockFd does not represent
 * a valid, open socket and sets errno to EBADF.  Otherwise, returns the result of
 * calling listen on the socket file descriptor passed with a backlog size of
 * BACKLOG_SIZE (128 by default).  Zero is returned if the operation was successful.
 */
int SocketDemoUtils_listen(int sockFd) {
	log_info("In SocketDemoUtils_listen");

	log_debug("SocketDemoUtils_listen: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_listen: Checking for a valid socket file descriptor...");

	if (sockFd <= 0) {
		log_error(
				"SocketDemoUtils_listen: Invalid socket file descriptor passed.");

		errno = EBADF;

		log_debug("SocketDemoUtils_listen: Set errno = %d", errno);

		log_debug("SocketDemoUtils_listen: Done.");

		return ERROR;   // Invalid socket file descriptor
	}

	log_info(
			"SocketDemoUtils_listen: A valid socket file descriptor has been passed.");

	int retval = listen(sockFd, BACKLOG_SIZE);

	log_debug("SocketDemoUtils_listen: retval = %d", retval);

	if (retval < 0) {
		log_error("SocketDemoUtils_listen: Failed to listen on socket.");

		log_debug("SocketDemoUtils_listen: Done.");

		return ERROR;
	}

	log_info("SocketDemoUtils_listen: Returning %d", retval);

	log_debug("SocketDemoUtils_listen: Done.");

	return retval;
}

/**
 * \brief Accepts an incoming connection on a socket and returns information about
 * the remote host.
 * \param sockFd Socket file descriptor on which to accept new incoming connections.
 * \param addr Reference to a sockaddr_in structure that receives information about
 * the IP address of the remote endpoint.
 * \returns Socket file descriptor representing the local endpoint of the new
 * incoming connection; or a negative number indicating that errno should be read
 * for the error description.
 * \remarks Returns ERROR if any of the following are true: (a) sets errno to EBADF
 * if sockFd is an invalid value (nonpositive) or (b) sets errno to EINVAL if addr
 * is NULL.  If the incoming connection is accepted successfully, this function also
 * calls fcntl on the new file descriptor to set the incoming socket connection to be
 * non-blocking.  This allows data to be read from recv buffer as it is still coming
 * in.  This function blocks the calling thread until an incoming connection has been
 * established.
 */
int SocketDemoUtils_accept(int sockFd, struct sockaddr_in *addr) {

	log_debug("In SocketDemoUtils_accept");

	int client_socket = ERROR;

	log_debug("SocketDemoUtils_accept: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_accept: Checking for a valid socket file descriptor...");

	if (sockFd <= 0) {
		log_error(
				"SocketDemoUtils_accept: Invalid file descriptor passed in sockFd parameter.");

		errno = EBADF;          // Bad file descriptor
		return client_socket;
	}

	log_info(
			"SocketDemoUtils_accept: We were passed a valid socket file descriptor.");

	log_info("SocketDemoUtils_accept: Checking whether we are passed a valid sockaddr_in reference...");

	if (addr == NULL) {
		log_error("SocketDemoUtils_accept: Null reference passed for sockaddr_in structure.  Stopping.");

		log_debug("SocketDemoUtils_accept: Done.");

		return ERROR;
	}

	log_info("SocketDemoUtils_accept: We have a valid reference to a sockaddr_in structure.");

	// We now call the accept function.  This function holds us up
	// until a new client connection comes in, whereupon it returns
	// a file descriptor that represents the socket on our side that
	// is connected to the client.
	log_info("SocketDemoUtils_accept: Calling accept...");

	socklen_t client_address_len = sizeof(*addr);

	if ((client_socket = accept(sockFd, (struct sockaddr*) addr, &client_address_len))
			< 0) {
		log_error(
				"SocketDemoUtils_accept: Invalid value returned from accept.");

		perror(NULL);

		log_debug("SocketDemoUtils_accept: client_socket = %d", client_socket);

		log_debug("SocketDemoUtils_accept: Done.");

		return client_socket;
	}

	log_info(
			"SocketDemoUtils_accept: Configuring server TCP endpoint to be non-blocking...");

	// Attempt to configure the server socket to be non-blocking, this way
	// we can hopefully receive data as it is being sent vs only getting
	// the data when the client closes the connection.
	/*if (fcntl(sockFd, F_SETFL, fcntl(sockFd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		 error_and_close(sockFd,
				 "SocketDemoUtils_accept: Could not set the server TCP endpoint to be non-blocking.");
	}*/

	log_info(
			"SocketDemoUtils_accept: Server TCP endpoint configured to be non-blocking.");

	log_info("SocketDemoUtils_accept: New client connected.");

	log_debug("SocketDemoUtils_accept: client_socket = %d", client_socket);

	log_debug("SocketDemoUtils_accept: Done.");

	return client_socket;
}

/** \brief Reads a line of data, terminated by the '\n' character, from a socket.
 *  \param sockFd Socket file descriptor from which to receive data.
 *  \param buf Reference to an address at which to allocate storage for the received data.
 *  \returns Total bytes read for the current line or a negative number otherwise.
 *  \remarks This function will forcibly terminate the calling program with an exit
 *  code of ERROR if the operation fails.  It is the responsibility of the caller to
 *  free the memory referenced by *buf.  The caller must always pass NULL for buf.  If
 *  valid storage is passed, this function will free the storage referenced by *buf and
 *  allocate brand-new storage for the incoming line.
 */
int SocketDemoUtils_recv(int sockFd, char **buf) {
	log_debug("In SocketDemoUtils_recv");

	log_debug("SocketDemoUtils_recv: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_recv: Checking whether the socket file descriptor passed is valid...");

	if (sockFd <= 0) {
		log_error(
				"SocketDemoUtils_recv: Invalid socket file descriptor passed.");

		log_debug("SocketDemoUtils_recv: Done.");

		exit(ERROR);
	}

	log_info(
			"SocketDemoUtils_recv: The socket file descriptor passed is valid.");

	log_info("SocketDemoUtils_recv: Checking for valid receive buffer...");

	if (buf == NULL) {
		log_error(
				"SocketDemoUtils_recv: Null reference passed for receive buffer.");

		log_debug("SocketDemoUtils_recv: Done.");

		exit(ERROR);
	}

	log_info(
			"SocketDemoUtils_recv: Valid memory storage reference passed for receive buffer.");

	int bytes_read = 0;
	int total_read = 0;

	log_info("SocketDemoUtils_recv: Allocating %d bytes for receive buffer...",
	RECV_BLOCK_SIZE);

	// Allocate up some brand-new storage of size RECV_BLOCK_SIZE
	// plus an extra slot to hold the null-terminator.  Free any
	// storage already referenced by *buf.  If *buf happens to be
	// NULL already, a malloc is done.  Once the new memory has been
	// allocated, we then explicitly zero it out.
	total_read = 0;
	*buf = (char*) realloc(*buf, (RECV_BLOCK_SIZE + 1) * sizeof(char));
	explicit_bzero((void*) *buf, RECV_BLOCK_SIZE + 1);

	//char prevch = '\0';
	while (1) {
		char ch;		// receive one char at a time
		bytes_read = recv(sockFd, &ch, RECV_BLOCK_SIZE, RECV_FLAGS);
		if (bytes_read < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;

			error("recv: Network error stopped us from receiving more text.");

			//prevch = ch;
			break;
		}

		// If we are here, then stuff came over the wire.
		// Stick the character received, from ch, into the next
		// storage element referenced by *buf + total_read
		// and then allocate some more memory to hold the
		// next char and then the null terminator
		*(*buf + total_read) = ch;

		// Tally the total bytes read overall
		total_read += bytes_read;

		// If the newline ('\n') character was the char received,
		// then we're done; it's time to apply the null terminator.
		if (ch == '\n') {
			break;
		}

		// re-allocate more memory and make sure to leave room
		// for the null-terminator.
		*buf = (char*) realloc(*buf,
				(total_read + RECV_BLOCK_SIZE + 1) * sizeof(char));
	}

	if (total_read > 0) {
		// We are done receiving, cap the string off with a null terminator
		// after resizing the buffer to match the total bytes read + 1.  if
		// a connection error happened prior to reading even one byte, then
		// total_read will be zero and the call below will be equivalent to
		// free.  strlen(*buf) will then return zero, and this will be
		// how we can tell not to call free() again on *buf
		*buf = (char*) realloc(*buf, (total_read + 1) * sizeof(char));
		*(*buf + total_read) = '\0';// cap the buffer off with the null-terminator
	}

	log_info("SocketDemoUtils_recv: %d bytes received.", total_read);

	// Now the storage at address *buf should contain the entire
	// line just received, plus the newline and the null-terminator, plus
	// any previously-received data

	log_debug("SocketDemoUtils_recv: Returning %d", total_read);

	log_debug("SocketDemoUtils_recv: Done.");

	return total_read;
}

/**
 *	\brief Sends data to the endpoint on the other end of the connection referenced
 *	by the connected socket.
 *	\param sockFd Socket file descriptor.  Must be a descriptor for a valid socket that
 *	is currently connected to a remote host.
 *	\param buf Address of a character array containing the bytes to be sent.
 *	\returns ERROR if the operation failed; number of bytes sent otherwise.
 *	If the ERROR value is returned, errno should be examined to determine the
 *  cause of the error.
 */
int SocketDemoUtils_send(int sockFd, const char *buf) {
	log_debug("In SocketDemoUtils_send");

	log_info("SocketDemoUtils_send: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_send: Checking whether we have been passed a valid socket file descriptor...");

	if (sockFd <= 0) {
		log_error(
				"SocketDemoUtils_send: Invalid socket file descriptor passed.");

		errno = EBADF;

		log_debug("SocketDemoUtils_send: errno set to %d", errno);

		log_debug("SocketDemoUtils_send: Done.");

		exit(ERROR);
	}

	log_info(
			"SocketDemoUtils_send: The socket file descriptor passed is valid.");

	log_info(
			"SocketDemoUtils_send: Checking whether text was passed in for sending...");

	if (buf == NULL || strlen(buf) <= 0 || buf[0] == '\0') {
		log_error(
				"SocketDemoUtils_send: Nothing was passed to us to send.  Stopping.");

		log_debug("SocketDemoUtils_send: Returning zero.");

		log_debug("SocketDemoUtils_send: Done.");

		// Nothing to send
		return 0;
	}

	int retval = (int) send(sockFd, buf, strlen(buf), 0);

	if (retval < 0) {
		error_and_close(sockFd, "SocketDemoUtils_send: Failed to send data.");
	}

	log_info("SocketDemoUtils_send: %d bytes sent.", retval);

	log_debug("SocketDemoUtils_send: Done.");

	return retval;
}

/**
 * \brief Connects a socket to a remote host whose hostname or IP address and
 * port number is specified.
 * \param sockFd Socket file descriptor representing a socket that is not yet
 * connected to a remote endpoint.
 * \param hostnameOrIp String indicating the human-readable (in DNS) hostname
 * or the IP address of the remote host.
 * \param port Port number that the service on the remote host is listening on.
 * \returns Zero if successful; ERROR if an error occurred.  The errno
 * value should be examined if this happens.  In other cases, this function
 * forcibly terminates the calling program with the ERROR exit code.
 */
int SocketDemoUtils_connect(int sockFd, const char *hostnameOrIp, int port) {
	log_debug("In SocketDemoUtils_connect");

	int result = ERROR;

	log_debug("SocketDemoUtils_connect: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_connect: Checking for a valid socket file descriptor...");

	if (sockFd <= 0) {
		log_error(
				"connect: Attempted to connect to remote host with no endpoint.");
		exit(result);
	}

	log_info(
			"SocketDemoUtils_connect: A valid socket file descriptor was passed.");

	log_info("SocketDemoUtils_connect: port = %d");

	log_info(
			"SocketDemoUtils_connect: Checking whether the port number used is valid...");

	if (!isUserPortValid(port)) {
		log_error(
				"SocketDemoUtils_connect: Port number must be in the range 1024-49151 inclusive.");

		log_debug("SocketDemoUtils_connect: Done.");

		exit(result);
	}

	log_info("SocketDemoUtils_connect: The port number in use is valid.");

	struct hostent *he;                    // Host entry
	struct sockaddr_in server_address; // Structure for the server address and port

	log_info(
			"SocketDemoUtils_connect: Attempting to resolve the hostname or IP address '%s'...",
			hostnameOrIp);

	// First, try to resolve the host name or IP address passed to us, to ensure that
	// the host can even be found on the network in the first place.  Calling the function
	// below also has the added bonus of filling in a hostent structure for us if it succeeds.
	if (!isValidHostnameOrIp(hostnameOrIp, &he)) {
		error_and_close(sockFd,
				"connect: Unable to validate/resolve hostname/IP address provided.");
	}

	log_info(
			"SocketDemoUtils_connect: The hostname or IP address passed could be resolved.");

	log_info(
			"SocketDemoUtils_connect: Attempting to contact the server at '%s' on port %d...",
			hostnameOrIp, port);

	/* copy the network address to sockaddr_in structure */
	memcpy(&server_address.sin_addr, he->h_addr_list[0], he->h_length);
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);

	if ((result = connect(sockFd, (struct sockaddr*) &server_address,
			sizeof(server_address))) < 0) {
		log_error(
				"SocketDemoUtils_connect: The attempt to contact the server at '%s' on port %d failed.",
				hostnameOrIp, port);

		log_debug("SocketDemoUtils_connect: Done.");

		SocketDemoUtils_close(sockFd);

		exit(ERROR);
	}

	log_info(
			"SocketDemoUtils_connect: Connected to the server at '%s' on port %d.",
			hostnameOrIp, port);

	log_info("SocketDemoUtils_connect: result = %d", result);

	log_debug("SocketDemoUtils_connect: Done.");

	return result;
}

void SocketDemoUtils_close(int sockFd) {
	log_debug("In SocketDemoUtils_close");

	log_debug("SocketDemoUtils_close: sockFd = %d", sockFd);

	log_info(
			"SocketDemoUtils_close: Checking for a valid socket file descriptor...");

	if (sockFd <= 0) {
		log_error(
				"SocketDemoUtils_close: Attempted to connect to remote host with no endpoint.");

		return;	// just silently fail if the socket file descriptor passed is invalid
	}

	log_info(
			"SocketDemoUtils_close: A valid socket file descriptor was passed.");

	log_info("SocketDemoUtils_close: Attempting to close the socket...");

	int retval = close(sockFd);

	if (retval < 0) {
		log_error("SocketDemoUtils_close: Failed to close the socket.");

		log_debug("SocketDemoUtils_close: Done.");

		return;
	}

	log_info("SocketDemoUtils_close: Socket closed successfully.");

	log_debug("SocketDemoUtils_close: Done.");
}
