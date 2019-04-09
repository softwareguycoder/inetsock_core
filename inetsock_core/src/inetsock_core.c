///////////////////////////////////////////////////////////////////////////////
// socketapi.c: Definitions for the functions in the SocketDemoUtils.lib
// shared library

#include "stdafx.h"
#include "inetsock_core.h"

#define CONNECT_OPERATION_FAILED "connect: Failed to contact server on '%s' and port %d.\n"

pthread_mutex_t* g_pSocketMutex; /* mutex for socket access */

void CreateSocketMutex() {
	log_debug("In CreateSocketMutex");

	log_debug(
			"CreateSocketMutex: Checking whether the socket mutex handle has already been created...");

	if (NULL != g_pSocketMutex) {
		log_debug(
				"CreateSocketMutex: Socket mutex handle already created.  Nothing to do.");

		log_debug("CreateSocketMutex: Done.");

		return;
	}

	log_debug(
			"CreateSocketMutex: The socket mutex handle has not been created yet.");

	log_debug(
			"CreateSocketMutex: Attempting to create and then initialize a new socket mutex handle...");

	g_pSocketMutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
	if (g_pSocketMutex == NULL) {
		log_error(
				"CreateSocketMutex: Failed to allocate memory for a new socket mutex handle.");

		perror("LockSocketMutex");

		exit(ERROR);
	}

	log_debug(
			"CreateSocketMutex: Successfully allocated storage for a socket mutex handle.");

	log_debug(
			"CreateSocketMutex: Attempting to initialize the socket mutex handle...");

	// Call pthread_mutex_init.  This version of CreateMutex just passes a
	// mutex handle for the function to initialize with NULL for the attributes.
	int nResult = pthread_mutex_init(g_pSocketMutex, NULL);
	if (OK != nResult) {
		log_error(
				"CreateSocketMutex: Failed to initialize the socket mutex handle.");

		// Cleanup the mutex handle if necessary
		if (NULL != g_pSocketMutex) {
			log_debug(
					"CreateSocketMutex: Attempting to release the system resources used by the handle...");

			FreeSocketMutex();

			log_debug("CreateSocketMutex: We called FreeSocketMutex.");
		}

		log_debug("CreateSocketMutex: Done.");

		perror("LockSocketMutex");
		exit(ERROR);
	}

	log_info(
			"CreateSocketMutex: Successfully initialized the socket mutex handle.");

	log_debug("CreateSocketMutex: Done.");
}

void FreeSocketMutex() {
	log_debug("In FreeSocketMutex");

	log_debug(
			"FreeSocketMutex: Checking whether g_pSocketMutex variable is NULL...");

	if (NULL == g_pSocketMutex) {
		log_debug(
				"FreeSocketMutex: The g_pSocketMutex variable has a null reference.  Nothing to do.");

		log_debug("FreeSocketMutex: Done.");

		return;
	}

	log_debug(
			"FreeSocketMutex: The g_pSocketMutex has a valid pthread_mutex_t reference.");

	/* Destroy the mutex handle for socket use.  We are utilizing the bare-bones pthread_mutex_t
	 * type and pthread_mutex_destory system API, rather than the functions exported by the mutex_core
	 * library.  This is to avoid an unncessary dependency.  That is, I do not want to have to drag
	 * in the mutex library every single time I want to use this inetsock_core library. */

	log_info("FreeSocketMutex: Attempting to destroy the socket mutex...");

	int retval = pthread_mutex_destroy(g_pSocketMutex);
	if (retval != OK) {
		perror("inetsock_core[FreeSocketMutex]");

		exit(ERROR);
	}

	log_info("FreeSocketMutex: Mutex destroyed successfully.");

	log_debug(
			"FreeSocketMutex: Attempting to release the resources associated with the g_pSocketMutex handle...");

	free(g_pSocketMutex);
	g_pSocketMutex = NULL;

	log_debug("FreeSocketMutex: Resources freed.");

	log_debug("FreeSocketMutex: Done.");
}

void LockSocketMutex() {
	log_debug("In LockSocketMutex");

	int nResult = ERROR;

	log_debug(
			"LockSocketMutex: Checking if the socket mutex handle has been initialized...");

	if (NULL == g_pSocketMutex) {
		// just do nothing. (g_pSocketMutex will have the value of NULL in the case
		// that the caller of this library did not call CreateSocketMutex in their
		// main function)

		log_debug(
				"LockSocketMutex: The socket mutex handle has not been initialized.  Nothing to do.");

		log_debug("LockSocketMutex: Done.");

		return; /* if we are here then we are not using mutexes at all */
	}

	log_debug("LockSocketMutex: The socket mutex handle is initialized.");

	log_debug(
			"LockSocketMutex: Attempting to obtain a lock on the socket mutex...");

	nResult = pthread_mutex_lock(g_pSocketMutex);
	if (OK != nResult) {
		log_error(
				"LockSocketMutex: Failed to obtain a lock on the socket mutex.");

		log_debug("LockSocketMutex: Done.");

		perror("LockSocketMutex");
		exit(ERROR);
	}

	log_debug("LockSocketMutex: A lock has been obtained on the socket mutex.");

	log_debug("LockSocketMutex: Done.");

	return; 	// Succeeded
}

void UnlockSocketMutex() {
	log_debug("In UnlockSocketMutex");

	log_debug(
			"UnlockSocketMutex: Checking whether the socket mutex handle has been initialized...");

	if (NULL == g_pSocketMutex) {
		// If the g_pSocketMutex handle is NULL, then assume that the caller of
		// this library is writing a single-threaded application which will not
		// need mutexes for its socket communications. Therefore, in this case,
		// just do nothing. (g_pSocketMutex will have the value of NULL in the case
		// that the caller of this library did not call CreateSocketMutex in their
		// main function)

		log_debug(
				"UnlockSocketMutex: The socket mutex handle has not been initialized.  Nothing to do.");

		log_debug("UnlockSocketMutex: Done.");

		return;
	}

	log_debug(
			"UnlockSocketMutex: The socket mutex handle has been initialized.");

	log_debug(
			"UnlockSocketMutex: Attempting to release the currently-active lock on the socket mutex...");

	int nResult = pthread_mutex_unlock(g_pSocketMutex);
	if (OK != nResult) {
		log_error(
				"UnlockSocketMutex: Failed to release the socket mutex lock.");

		log_debug("UnlockSocketMutex: Done.");

		perror("UnlockSocketMutex");
		exit(ERROR);
	}

	log_debug("UnlockSocketMutex: The socket mutex lock has been released.");

	log_debug("UnlockSocketMutex: Done.");
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
	log_debug("In IsHostnameValid");

	log_debug("hostnameOrIP: hostnameOrIP = %s", hostnameOrIP);

	log_info(
			"IsHostnameValid: Checking whether the 'hostnameOrIP' parameter is blank...");

	if (hostnameOrIP == NULL || hostnameOrIP[0] == '\0'
			|| strlen(hostnameOrIP) == 0) {
		// The hostnameOrIP parameter cannot be blank, since we need to find
		// out if the hostname or IP supplied is valid.  Can't very well do that
		// for a blank value!

		log_error(
				"hostnameOrIP parameter is blank.  This parameter is required to have a value.");

		log_debug("IsHostnameValid: Returning FALSE.");

		log_debug("IsHostnameValid: Done.");

		return FALSE;
	}

	log_info("IsHostnameValid: The 'hostnameOrIP' parameter has a value.");

	log_info(
			"IsHostnameValid: Checking whether the 'he' parameter has a value...");

	if (he == NULL) {

		log_error("IsHostnameValid: The 'he' parameter has a null reference.");

		log_debug("IsHostnameValid: Returning FALSE.");

		log_debug("IsHostnameValid: Done.");

		// return FALSE if no storage location for the 'he' pointer passed
		return FALSE;
	}

	log_info("IsHostnameValid: The 'he' parameter has a value.");

	log_info(
			"IsHostnameValid: Attempting to obtain a lock on the socket mutex...");

	LockSocketMutex();
	{
		log_info(
				"IsHostnameValid: Lock obtained on the socket mutex, or no mutex was created.");

		log_info("IsHostnameValid: Resolving host name or IP address '%s'...",
				hostnameOrIP);

		if ((*he = gethostbyname(hostnameOrIP)) == NULL) {
			log_error(
					"IsHostnameValid: Hostname or IP address resolution failed.");

			*he = NULL;

			log_info("IsHostnameValid: 'he' parameter set to NULL.");

			log_debug("IsHostnameValid: Returning FALSE.");

			log_debug("IsHostnameValid: Done.");

			log_info("IsHostnameValid: Releasing socket mutex lock...");

			UnlockSocketMutex();

			log_info("IsHostnameValid: Socket mutex lock released.");

			// return FALSE if no storage location for the 'he' pointer passed
			return FALSE;
		}

		log_info("IsHostnameValid: Releasing socket mutex lock...");
	}
	UnlockSocketMutex();

	log_info("IsHostnameValid: Socket mutex lock released.");

	log_info("IsHostnameValid: Hostname or IP address resolution succeeded.");

	log_debug("IsHostnameValid: Returning TRUE.");

	log_debug("IsHostnameValid: Done.");

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
	log_debug("In IsSocketValid");

	log_debug("IsSocketValid: sockFD = %d", sockFD);

	log_debug(
			"IsSocketValid: Checking whether the socket file descriptor passed has a valid value...");

	/* Linux socket file descriptors are always positive, nonzero
	 * integers when they represent a valid socket handle.
	 */
	if (sockFD <= 0) {
		log_error(
				"IsSocketValid: Socket file descriptor is not a valid value.");

		log_debug("IsSocketValid: Result = FALSE");

		log_debug("IsSocketValid: Done.");

		return FALSE;
	}

	log_debug("IsSocketValid: Socket file descriptor passed is valid.");

	log_debug("IsSocketValid: Result = TRUE");

	log_debug("IsSocketValid: Done.");

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

	log_error(msg);
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

	log_error(msg);
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
	log_debug("In CreateSocket");

	int sockFd = -1;

	log_info(
			"CreateSocket: Attempting to obtain a lock on the socket mutex...");

	LockSocketMutex();
	{
		log_info(
				"CreateSocket: Socket mutex lock obtained, or we are not using it.");

		log_info("CreateSocket: Attempting to create new TCP endpoint...");

		sockFd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockFd <= 0) {
			log_error("CreateSocket: Could not create new TCP endpoint.");

			UnlockSocketMutex();

			FreeSocketMutex();

			log_debug("CreateSocket: Done.");

			exit(ERROR);
		}

		log_debug(
				"CreateSocket: Attempting to release the socket mutex lock...");
	}
	UnlockSocketMutex();

	log_debug("CreateSocket: Socket mutex lock released.");

	log_info("CreateSocket: Endpoint created successfully.");

	log_info("CreateSocket: Attempting to mark endpoint as reusable...");

	SetSocketReusable(sockFd);

	log_info("CreateSocket: Endpoint configured to be reusable.");

	log_info("CreateSocket: The new socket file descriptor is %d.", sockFd);

	log_debug("CreateSocket: Done.");

	return sockFd;
}

void SetSocketNonBlocking(int sockFd) {

	if (!IsSocketValid(sockFd)) {
		return;
	}

	int flags = 0;

	/* Set socket to non-blocking */

	if ((flags = fcntl(sockFd, F_GETFL, 0)) < 0)
	{
	    return;
	}


	if (fcntl(sockFd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
	    return;
	}
}

int SetSocketReusable(int sockFd) {
	log_debug("In SetSocketReusable");

	int retval = ERROR;

	log_info(
			"SetSocketReusable: Checking whether a valid socket file descriptor was passed...");

	if (sockFd <= 0) {
		log_error(
				"SetSocketReusable: The socket file descriptor has an invalid value.");

		log_debug("SetSocketReusable: Done.");

		return retval;
	}

	log_info(
			"SetSocketReusable: A valid socket file descriptor has been passed.");

	log_debug(
			"SetSocketReusable: Attempting to obtain a lock on the socket mutex...");

	// Set socket options to allow the socket to be reused.
	LockSocketMutex();
	{
		log_debug(
				"SetSocketReusable: Socket mutex lock obtained, or not using it.");

		log_info(
				"SetSocketReusable: Attempting to set the socket as reusable...");

		retval = setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &(int ) { 1 },
				sizeof(int));
		if (retval < 0) {
			perror("setsockopt");

			log_error("SetSocketReusable: Failed to mark socket as reusable.");

			log_debug(
					"SetSocketReusable: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug(
					"SetSocketReusable: Socket mutex lock has been released.");

			log_debug("SetSocketReusable: Done.");

			return retval;
		}

		log_info(
				"SetSocketReusable: Socket configuration operation succeeded.");

		log_debug(
				"SetSocketReusable: Attempting to release the socket mutex lock...");
	}
	UnlockSocketMutex();

	log_debug("SetSocketReusable: Socket mutex lock released.");

	log_debug("SetSocketReusable: retval = %d", retval);

	log_debug("SetSocketReusable: Done.");

	return retval;
}

/**
 * @brief Populates the port and address information for a server
 *  so the server knows the hostname/IP address and port of the computer
 *  it is listening on.
 * @param port String containing the port number to listen on.  Must be numeric.
 * @param hostnameOrIp String containing the hostname or IP address of the server
 *  computer.  Can be NULL, in which case, htons(INADDR_ANY) will be set.  Use NULL
 *  for a sevrer, and a specific value for a client.
 * @param addr Address of storage that will receive a filled-in sockaddr_in structure
 *  that defines the server endpoint.
 * @remarks If invalid input is supplied or an error occurs, reports thse problem
 *  to the console and forces the program to die with the ERROR exit code.
 */
void GetServerAddrInfo(const char *port, struct sockaddr_in *addr) {

	log_info("In GetServerAddrInfo");

	log_debug("GetServerAddrInfo: Obtaining a lock on the socket mutex...");

	LockSocketMutex();
	{
		log_debug(
				"GetServerAddrInfo: Lock obtained on socket mutex or it's not needed.");

		log_info("GetServerAddrInfo: port = '%s'", port);

		log_info(
				"GetServerAddrInfo: Checking whether the 'port' parameter has a value...");

		if (port == NULL || strlen(port) == 0 || port[0] == '\0') {
			log_error(
					"GetServerAddrInfo: String containing the port number is blank.");

			log_debug(
					"GetServerAddrInfo: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug(
					"GetServerAddrInfo: Socket mutex lock has been released.");

			log_debug(
					"GetServerAddrInfo: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("GetServerAddrInfo: Socket mutex resources freed.");

			log_debug("GetServerAddrInfo: Done.");

			exit(ERROR);
		}

		if (addr == NULL) {
			log_error(
					"GetServerAddrInfo: Missing pointer to a sockaddr_in structure.");

			log_debug(
					"GetServerAddrInfo: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug(
					"GetServerAddrInfo: Socket mutex lock has been released.");

			log_debug(
					"GetServerAddrInfo: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("GetServerAddrInfo: Socket mutex resources freed.");

			log_debug("GetServerAddrInfo: Done.");

			exit(ERROR);
		}

		// Get the port number from its string representation and then validate that it is in
		// the proper range
		int portnum = 0;
		int result = char_to_long(port, (long*) &portnum);
		if (result >= 0 && !isUserPortValid(portnum)) {
			log_error(
					"GetServerAddrInfo: Port number must be in the range 1024-49151 inclusive.");

			log_debug(
					"GetServerAddrInfo: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug(
					"GetServerAddrInfo: Socket mutex lock has been released.");

			log_debug(
					"GetServerAddrInfo: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("GetServerAddrInfo: Socket mutex resources freed.");

			log_debug("GetServerAddrInfo: Done.");

			exit(ERROR);
		}

		// Populate the fields of the sockaddr_in structure passed to us with the proper values.

		log_info("GetServerAddrInfo: Configuring server address and port...");

		addr->sin_family = AF_INET;
		addr->sin_port = htons(portnum);
		addr->sin_addr.s_addr = htons(INADDR_ANY);

		log_info("GetServerAddrInfo: Server configured to listen on port %d.",
				portnum);

		log_debug(
				"GetServerAddrInfo: Attempting to release the socket mutex lock...");
	}
	UnlockSocketMutex();

	log_debug("GetServerAddrInfo: The socket mutex lock has been released.");

	log_debug("GetServerAddrInfo: Done.");
}

/**
 * @brief Binds a server socket to the address and port specified by the 'addr'
 *   parameter.
 * @param sockFd Socket file descriptor that references the socket to be bound.
 * @param addr Pointer to a sockaddr_in structure that specifies the host and port
 *  to which the socket endpoint should be bound.
 */
int BindSocket(int sockFd, struct sockaddr_in *addr) {
	log_debug("In BindSocket");

	int retval = ERROR;

	LockSocketMutex();
	{
		log_debug("BindSocket: sockFd = %d", sockFd);

		log_info(
				"BindSocket: Checking whether a valid socket file descriptor was passed...");

		if (sockFd <= 0) {
			log_error("BindSocket: Invalid socket file descriptor passed.");

			errno = EBADF;

			log_debug("BindSocket: Set errno = %d", errno);

			perror("BindSocket");

			log_debug(
					"BindSocket: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("BindSocket: Socket mutex lock has been released.");

			log_debug(
					"BindSocket: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("BindSocket: Socket mutex resources freed.");

			log_debug("BindSocket: Done.");

			exit(ERROR);
		}

		log_info("BindSocket: A valid socket file descriptor has been passed.");

		log_info(
				"BindSocket: Checking whether a valid sockaddr_in reference has been passed...");

		if (addr == NULL) {
			log_error(
					"BindSocket: A null reference has been passed for the 'addr' parameter.  Nothing to do.");

			errno = EINVAL; // addr param required

			log_debug("BindSocket: Set errno = %d", errno);

			perror("BindSocket");

			log_debug(
					"BindSocket: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("BindSocket: Socket mutex lock has been released.");

			log_debug(
					"BindSocket: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("BindSocket: Socket mutex resources freed.");

			log_debug("BindSocket: Done.");

			exit(ERROR);
		}

		log_info("BindSocket: A valid sockaddr_in reference has been passed.");

		log_info(
				"BindSocket: Attempting to bind socket %d to the server address...",
				sockFd);

		retval = bind(sockFd, (struct sockaddr*) addr, sizeof(*addr));

		log_debug("BindSocket: retval = %d", retval);

		if (retval < 0) {
			log_error("BindSocket: Failed to bind socket.");

			log_debug("BindSocket: errno = %d", errno);

			perror("BindSocket");

			log_debug(
					"BindSocket: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("BindSocket: Socket mutex lock has been released.");

			log_debug(
					"BindSocket: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("BindSocket: Socket mutex resources freed.");

			log_debug("BindSocket: Done.");

			exit(ERROR);
		}

		log_info("BindSocket: Successfully bound the server socket.");

		log_debug("BindSocket: Attemtping to release the socket mutex lock...");
	}
	UnlockSocketMutex();

	log_debug("BindSocket: Released the socket mutex lock.");

	log_info("BindSocket: Returning %d", retval);

	log_debug("BindSocket: Done.");

	return retval;
}

/**
 * @brief Sets up a TCP or UDP server socket to listen on a port and IP address
 * to which it has been bound previously with the BindSocket function.
 * @params sockFd Socket file descriptor.
 * @returns ERROR if the socket file descriptor passed in sockFd does not represent
 * a valid, open socket and sets errno to EBADF.  Otherwise, returns the result of
 * calling listen on the socket file descriptor passed with a backlog size of
 * BACKLOG_SIZE (128 by default).  Zero is returned if the operation was successful.
 */
int ListenSocket(int sockFd) {
	log_info("In ListenSocket");

	int retval = ERROR;

	log_debug(
			"ListenSocket: Attempting to obtain a lock on the socket mutex...");

	LockSocketMutex();
	{
		log_debug("ListenSocket: Socket mutex has been locked.");

		log_info(
				"ListenSocket: Checking for a valid socket file descriptor...");

		log_debug("ListenSocket: sockFd = %d", sockFd);

		if (sockFd <= 0) {
			log_error("ListenSocket: Invalid socket file descriptor passed.");

			errno = EBADF;

			log_debug("ListenSocket: Set errno = %d", errno);

			perror("ListenSocket");

			log_debug(
					"ListenSocket: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("ListenSocket: Socket mutex lock has been released.");

			log_debug(
					"ListenSocket: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("ListenSocket: Socket mutex resources freed.");

			log_debug("ListenSocket: Done.");

			exit(ERROR);
		}

		log_debug(
				"ListenSocket: A valid socket file descriptor has been passed.");

		log_info("ListenSocket: Calling the listen function...");

		retval = listen(sockFd, BACKLOG_SIZE);

		log_debug("ListenSocket: The listen function has been called.");

		log_debug("ListenSocket: retval = %d", retval);

		if (retval < 0) {
			log_error("ListenSocket: Failed to listen on socket.");

			perror("ListenSocket");

			log_debug(
					"ListenSocket: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("ListenSocket: Socket mutex lock has been released.");

			log_debug(
					"ListenSocket: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("ListenSocket: Socket mutex resources freed.");

			log_debug("ListenSocket: Done.");

			exit(ERROR);
		}

		log_info("ListenSocket: Listen operation successful.");

		log_debug("ListenSocket: Releasing the socket mutex lock...");
	}
	UnlockSocketMutex();

	log_debug("ListenSocket: Socket mutex lock released.");

	log_info("ListenSocket: Returning %d", retval);

	log_debug("ListenSocket: Done.");

	return retval;
}

/**
 * @brief Accepts an incoming connection on a socket and returns information about
 * the remote host.
 * @param sockFd Socket file descriptor on which to accept new incoming connections.
 * @param addr Reference to a sockaddr_in structure that receives information about
 * the IP address of the remote endpoint.
 * @returns Socket file descriptor representing the local endpoint of the new
 * incoming connection; or a negative number indicating that errno should be read
 * for the error description.
 * @remarks Returns ERROR if any of the following are true: (a) sets errno to EBADF
 * if sockFd is an invalid value (nonpositive) or (b) sets errno to EINVAL if addr
 * is NULL.  If the incoming connection is accepted successfully, this function also
 * calls fcntl on the new file descriptor to set the incoming socket connection to be
 * non-blocking.  This allows data to be read from recv buffer as it is still coming
 * in.  This function blocks the calling thread until an incoming connection has been
 * established.
 */
int AcceptSocket(int sockFd, struct sockaddr_in *addr) {

	log_debug("In AcceptSocket");

	int client_socket = ERROR;

	log_debug("AcceptSocket: sockFd = %d", sockFd);

	log_info("AcceptSocket: Checking for a valid socket file descriptor...");

	if (sockFd <= 0) {
		log_error(
				"AcceptSocket: Invalid file descriptor passed in sockFd parameter.");

		errno = EBADF;

		perror("AcceptSocket");

		log_debug("AcceptSocket: Attempting to free socket mutex resources...");

		FreeSocketMutex();

		log_debug("AcceptSocket: Socket mutex resources freed.");

		log_debug("AcceptSocket: Done.");

		exit(ERROR);
	}

	log_info("AcceptSocket: We were passed a valid socket file descriptor.");

	log_info(
			"AcceptSocket: Checking whether we are passed a valid sockaddr_in reference...");

	if (addr == NULL) {
		log_error(
				"AcceptSocket: Null reference passed for sockaddr_in structure.  Stopping.");

		errno = EINVAL;

		perror("AcceptSocket");

		log_debug("AcceptSocket: Attempting to free socket mutex resources...");

		FreeSocketMutex();

		log_debug("AcceptSocket: Socket mutex resources freed.");

		log_debug("AcceptSocket: Attempting to close the server endpoint...");

		CloseSocket(sockFd);

		log_debug("AcceptSocket: Server endpoint resources released.");

		log_debug("AcceptSocket: Done.");

		exit(ERROR);
	}

	log_info(
			"AcceptSocket: We have a valid reference to a sockaddr_in structure.");

	// We now call the accept function.  This function holds us up
	// until a new client connection comes in, whereupon it returns
	// a file descriptor that represents the socket on our side that
	// is connected to the client.
	log_info("AcceptSocket: Calling accept...");

	socklen_t client_address_len = sizeof(*addr);

	if ((client_socket = accept(sockFd, (struct sockaddr*) addr,
			&client_address_len)) < 0) {
		log_error("AcceptSocket: Invalid value returned from accept.");

		if (EBADF != errno) {
			perror("AcceptSocket");

			log_debug(
					"AcceptSocket: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("AcceptSocket: Socket mutex resources freed.");

			log_debug(
					"AcceptSocket: Attempting to close the server endpoint...");

			CloseSocket(sockFd);

			log_debug("AcceptSocket: Server endpoint resources released.");
		}

		log_debug("AcceptSocket: Done.");

		/* If errno is EBADF, this is just from a thread being terminated outside of this
		 * accept() call. In this case, merely return an invalid socket file descriptor
		 * value instead of forcibly terminating the program.  If errno is anything else
		 * besides EBADF, then forcibly exit. */

		if (EBADF == errno) {
			return ERROR;
		} else {
			exit(ERROR);
		}
	}

	/*log_info(
	 "AcceptSocket: Configuring server TCP endpoint to be non-blocking...");*/

	// Attempt to configure the server socket to be non-blocking, this way
	// we can hopefully receive data as it is being sent vs only getting
	// the data when the client closes the connection.
	/*if (fcntl(sockFd, F_SETFL, fcntl(sockFd, F_GETFL, 0) | O_NONBLOCK) < 0) {
	 error_and_close(sockFd,
	 "AcceptSocket: Could not set the server TCP endpoint to be non-blocking.");
	 }*/

	/*log_info(
	 "AcceptSocket: Server TCP endpoint configured to be non-blocking.");*/

	log_info("AcceptSocket: New client connected.");

	log_debug("AcceptSocket: client_socket = %d", client_socket);

	log_debug("AcceptSocket: Done.");

	return client_socket;
}

/**
 * @brief Reads a line of data, terminated by the '\n' character, from a socket.
 * @param sockFd Socket file descriptor from which to receive data.
 * @param buf Reference to an address at which to allocate storage for the received data.
 * @returns Total bytes read for the current line or a negative number otherwise.
 * @remarks This function will forcibly terminate the calling program with an exit
 *  code of ERROR if the operation fails.  It is the responsibility of the caller to
 *  free the memory referenced by *buf.  The caller must always pass NULL for buf.  If
 *  valid storage is passed, this function will free the storage referenced by *buf and
 *  allocate brand-new storage for the incoming line.
 */
int Receive(int sockFd, char **buf) {
	log_debug("In Receive");

	int total_read = 0;

	log_debug("Receive: Attempting to obtain a lock on the socket mutex...");

	LockSocketMutex();
	{
		log_debug("Receive: Socket mutex lock obtained.");

		log_info(
				"Receive: Checking whether the socket file descriptor passed is valid...");

		log_debug("Receive: sockFd = %d", sockFd);

		if (sockFd <= 0) {
			log_error("Receive: Invalid socket file descriptor passed.");

			errno = EBADF;

			perror("Receive");

			log_debug(
					"Receive: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("Receive: Socket mutex lock has been released.");

			log_debug("Receive: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("Receive: Socket mutex resources freed.");

			log_debug("Receive: Done.");

			exit(ERROR);
		}

		log_info("Receive: The socket file descriptor passed is valid.");

		log_info("Receive: Checking for valid receive buffer...");

		if (buf == NULL) {
			log_error("Receive: Null reference passed for receive buffer.");

			perror("Receive");

			log_debug(
					"Receive: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("Receive: Socket mutex lock has been released.");

			log_debug("Receive: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("Receive: Socket mutex resources freed.");

			log_debug("Receive: Done.");

			exit(ERROR);
		}

		log_info(
				"Receive: Valid memory storage reference passed for receive buffer.");

		log_info("Receive: Initializing the receive buffer...");

		int bytes_read = 0;

		// Allocate up some brand-new storage of size RECV_BLOCK_SIZE
		// plus an extra slot to hold the null-terminator.  Free any
		// storage already referenced by *buf.  If *buf happens to be
		// NULL already, a malloc is done.  Once the new memory has been
		// allocated, we then explicitly zero it out.
		int initial_recv_buffer_size = RECV_BLOCK_SIZE + 1;

		log_info("Receive: Allocating %d B for receive buffer...",
				initial_recv_buffer_size);

		total_read = 0;
		*buf = (char*) realloc(*buf, initial_recv_buffer_size * sizeof(char));
		explicit_bzero((void*) *buf, initial_recv_buffer_size);

		log_info("Receive: Allocated %d B for receive buffer.",
				initial_recv_buffer_size);

		//char prevch = '\0';
		while (1) {
			char ch;		// receive one char at a time
			bytes_read = recv(sockFd, &ch, RECV_BLOCK_SIZE, RECV_FLAGS);
			if (bytes_read < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;

				//log_warning("Receive: Stopped receiving more text.");

				//log_info("Receive: Breaking out of recv loop...");

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
				//log_info("Receive: Newline encountered.");

				//log_info("Receive: Breaking out of recv loop...");

				break;
			}

			//log_info("Receive: Char received: '%c'", ch);

			//log_info("Receive: Expanding buffer to fit next char...");

			// re-allocate more memory and make sure to leave room
			// for the null-terminator.

			int new_recv_buffer_size = (total_read + RECV_BLOCK_SIZE + 1)
					* sizeof(char);

			*buf = (char*) realloc(*buf, new_recv_buffer_size);

			/*log_info("Receive: New receive buffer size is: %d B.",
					new_recv_buffer_size);*/
		}

		log_info("Receive: %d B have been received.", total_read);

		log_info(
				"Receive: Checking whether bytes received is a positive quantity...");

		if (total_read > 0) {
			log_info("Receive: Bytes received is a positive quantity.");

			// We are done receiving, cap the string off with a null terminator
			// after resizing the buffer to match the total bytes read + 1.  if
			// a connection error happened prior to reading even one byte, then
			// total_read will be zero and the call below will be equivalent to
			// free.  strlen(*buf) will then return zero, and this will be
			// how we can tell not to call free() again on *buf

			*buf = (char*) realloc(*buf, (total_read + 1) * sizeof(char));
			*(*buf + total_read) = '\0';// cap the buffer off with the null-terminator

			log_debug("Receive: Finished placing content into receive buffer.");
		} else {
			log_error("Receive: Total bytes received is a negative quantity.");

			log_info("Receive: Freeing memory allocated for receiving text...");

			free_buffer((void**)buf);

			log_info("Receive: Memory for receiving text has been released.");

			log_info("Receive: Releasing the socket mutex...");

			UnlockSocketMutex();

			log_info("Receive: Socket mutex released.");

			log_info("Receive: Closing the socket..");

			CloseSocket(sockFd);

			log_info("Receive: Socket closed.");

			log_info("Receive: Freeing the memory occupied by the socket mutex...");

			FreeSocketMutex();

			log_info("Receive: Socket mutex memory freed.");

			log_debug("Receive: Forcibly terminating executable...");

			exit(ERROR);
		}

		// Now the storage at address *buf should contain the entire
		// line just received, plus the newline and the null-terminator, plus
		// any previously-received data

		log_info("Receive: Releasing socket mutex...");
	}
	UnlockSocketMutex();

	log_info("Receive: Socket mutex releaed.");

	log_debug("Receive: Returning %d (total B read)", total_read);

	log_debug("Receive: Done.");

	return total_read;
}

/**
 * @brief Helper function to guarantee that entire message provided gets sent over a socket.
 * @param sockFd File descriptor for the socket.  Socket must be in the connected state.
 * @param buffer Reference to the start of the buffer containing the message to be sent.
 * @param length Size of the buffer to be used for sending.
 * @return Total number of bytes sent, or -1 if an error occurred.
 * @remarks This function will kill the program after spitting out an error message if something goes wrong.
 */
int SendAll(int sockFd, const char *message, size_t length) {
	log_debug("In SendAll");

	int total_bytes_sent = 0;

	log_debug("SendAll: Getting lock on socket mutex...");

	LockSocketMutex();
	{
		log_debug("SendAll: Lock obtained on socket mutex.");

		log_debug(
				"SendAll: Checking whether socket file descriptor is a valid value...");

		log_debug("SendAll: sockFd = %d", sockFd);

		if (sockFd <= 0) {
			log_error("SendAll: Invalid socket file descriptor.");

			log_error("SendAll: Invalid socket file descriptor passed.");

			errno = EBADF;

			perror("SendAll");

			log_debug(
					"SendAll: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("SendAll: Socket mutex lock has been released.");

			log_debug("SendAll: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("SendAll: Socket mutex resources freed.");

			log_debug("SendAll: Done.");

			exit(ERROR);
		}

		log_info("SendAll: A valid socket file descriptor was passed.");

		log_info(
				"SendAll: Checking whether the buffer of text to send is empty...");

		if (message == NULL || ((char*) message)[0] == '\0'
				|| strlen((char*) message) == 0) {
			log_error(
					"SendAll: Send buferr is empty.  This value is required.");

			errno = EINVAL;

			perror("SendAll");

			log_debug(
					"SendAll: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("SendAll: Socket mutex lock has been released.");

			log_debug("SendAll: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("SendAll: Socket mutex resources freed.");

			log_debug("SendAll: Done.");

			exit(ERROR);
		}

		log_info("SendAll: The send buffer is not empty.");

		char *trimmed_message = Trim(message);

		log_info("SendAll: message = '%s'", trimmed_message);

		// The Trim function uses malloc to produce its result
		free((void*) trimmed_message);
		trimmed_message = NULL;

		log_info(
				"SendAll: Checking whether the send buffer's size is a positive value...");

		log_info("SendAll: length = %d", (int) length);

		if ((int) length <= 0) {
			log_error("SendAll: Length should be a positive nonzero quanity.");

			errno = EINVAL;

			perror("SendAll");

			log_debug(
					"SendAll: Attempting to release the socket mutex lock...");

			UnlockSocketMutex();

			log_debug("SendAll: Socket mutex lock has been released.");

			log_debug("SendAll: Attempting to free socket mutex resources...");

			FreeSocketMutex();

			log_debug("SendAll: Socket mutex resources freed.");

			log_debug("SendAll: Done.");

			exit(ERROR);
		}

		char *ptr = (char*) message;

		int remaining = (int) length;

		log_info("SendAll: Starting send loop...");

		log_debug("SendAll: total_bytes_sent = %d B", total_bytes_sent);

		log_debug("SendAll: remaining = %d B", remaining);

		while (total_bytes_sent < remaining) {
			log_info("SendAll: Calling socket send function...");

			int bytes_sent = send(sockFd, ptr, length, 0);

			log_debug("SendAll: bytes_sent = %d B", bytes_sent);

			if (bytes_sent < 1) {
				perror("SendAll");

				log_debug(
						"SendAll: Attempting to release the socket mutex lock...");

				UnlockSocketMutex();

				log_debug("SendAll: Socket mutex lock has been released.");

				log_debug(
						"SendAll: Attempting to free socket mutex resources...");

				FreeSocketMutex();

				log_debug("SendAll: Socket mutex resources freed.");

				log_debug("SendAll: Done.");

				exit(ERROR);
			}

			log_debug("SendAll: Updating counters...");

			total_bytes_sent += bytes_sent;

			ptr += bytes_sent;
			remaining -= bytes_sent;

			log_debug("SendAll: total_bytes_sent = %d B", total_bytes_sent);

			log_debug("SendAll: remaining = %d B", remaining);
		}

		log_debug("SendAll: Sending complete.");

		log_debug("SendAll: Releasing socket mutex lock...");
	}
	UnlockSocketMutex();

	log_debug("SendAll: Socket mutex lock released.");

	log_info("SendAll: Result = %d B total sent.", total_bytes_sent);

	log_debug("SendAll: Done.");

	return total_bytes_sent;
}

int Send(int sockFd, const char *buf) {
	log_debug("In Send");

	log_info(
			"Send: Checking whether we have been passed a valid socket file descriptor...");

	log_debug("Send: sockFd = %d", sockFd);

	if (sockFd <= 0) {
		log_error("Send: Invalid socket file descriptor passed.");

		errno = EBADF;

		log_debug("Send: errno set to %d", errno);

		log_debug("Send: Done.");

		exit(ERROR);
	}

	log_info("Send: The socket file descriptor passed is valid.");

	log_info("Send: Checking whether text was passed in for sending...");

	if (buf == NULL || strlen(buf) <= 0 || buf[0] == '\0') {
		log_error("Send: Nothing was passed to us to send.  Stopping.");

		log_debug("Send: Returning zero.");

		log_debug("Send: Done.");

		// Nothing to send
		return 0;
	}

	log_info("Send: We were supplied with text for sending.");

	int buf_len = strlen(buf);

	log_info("Send: buf_len = %d", buf_len);

	log_info("Send: Now attempting the send operation...");

	int bytes_sent = SendAll(sockFd, buf, buf_len);

	log_info("Send: Sent %d bytes.", bytes_sent);

	if (bytes_sent < 0) {
		log_error("Send: Failed to send data.");

		error_and_close(sockFd, "Send: Failed to send data.");

		log_debug("Send: Attempting to free socket mutex resources...");

		FreeSocketMutex();

		log_debug("Send: Socket mutex resources freed.");

		log_debug("Send: Done.");

		exit(ERROR);
	}

	log_info("Send: %d B sent.", bytes_sent);

	log_debug("Send: Done.");

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
	log_debug("In ConnectSocket");

	int result = ERROR;

	log_debug("ConnectSocket: sockFd = %d", sockFd);

	log_info("ConnectSocket: Checking for a valid socket file descriptor...");

	if (!IsSocketValid(sockFd)) {
		log_error(
				"ConnectSocket: Attempted to connect to remote host with no endpoint.");
		exit(result);
	}

	log_info("ConnectSocket: A valid socket file descriptor was passed.");

	log_info("ConnectSocket: port = %d", port);

	log_info(
			"ConnectSocket: Checking whether the port number used is valid...");

	if (!isUserPortValid(port)) {
		if (stderr != get_error_log_file_handle()) {
			fprintf(stderr,
					"ConnectSocket: An invalid value is being used for the port number of the server.");
		}

		log_error(
				"ConnectSocket: Port number must be in the range 1024-49151 inclusive.");

		log_info("ConnectSocket: Attempting to close the socket...");

		CloseSocket(sockFd);

		log_info("ConnectSocket: Socket closed.");

		log_info("ConnectSocket: Attempting to release the socket mutex...");

		FreeSocketMutex();

		log_info("ConnectSocket: Resources for socket mutex have been freed.");

		log_debug("ConnectSocket: Done.");

		exit(result);
	}

	log_info("ConnectSocket: The port number in use is valid.");

	struct hostent *he;                    // Host entry
	struct sockaddr_in server_address; // Structure for the server address and port

	log_info(
			"ConnectSocket: Attempting to resolve the hostname or IP address '%s'...",
			hostnameOrIp);

	// First, try to resolve the host name or IP address passed to us, to ensure that
	// the host can even be found on the network in the first place.  Calling the function
	// below also has the added bonus of filling in a hostent structure for us if it succeeds.
	if (!IsHostnameValid(hostnameOrIp, &he)) {
		log_error("ConnectSocket: Cannot connect to server on '%s'.",
				hostnameOrIp);

		if (get_error_log_file_handle() != stderr) {
			fprintf(stderr, "ConnectSocket: Cannot connect to server on '%s'.",
					hostnameOrIp);
		}

		log_info("ConnectSocket: Attempting to close the socket...");

		CloseSocket(sockFd);

		log_info("ConnectSocket: Socket closed.");

		log_info("ConnectSocket: Attempting to release the socket mutex...");

		FreeSocketMutex();

		log_info("ConnectSocket: Resources for socket mutex have been freed.");

		log_debug("ConnectSocket: Done.");

		exit(result);
	}

	log_info(
			"ConnectSocket: The hostname or IP address passed could be resolved.");

	log_info("ConnectSocket: Obtaining a lock on the socket mutex...");

	LockSocketMutex();
	{
		log_info(
				"ConnectSocket: Lock on socket mutex obtained, or it was not necessary.");

		log_info(
				"ConnectSocket: Attempting to contact the server at '%s' on port %d...",
				hostnameOrIp, port);

		/* copy the network address to sockaddr_in structure */
		memcpy(&server_address.sin_addr, he->h_addr_list[0], he->h_length);
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(port);

		if ((result = connect(sockFd, (struct sockaddr*) &server_address,
				sizeof(server_address))) < 0) {
			log_error(
					"ConnectSocket: The attempt to contact the server at '%s' on port %d failed.",
					hostnameOrIp, port);

			log_info(
					"ConnectSocket: Releasing the lock on the socket mutex...");

			UnlockSocketMutex();

			log_info("ConnectSocket: Socket mutex lock released.");

			log_info(
					"ConnectSocket: Releasing operating system resources consumed by the socket mutex...");

			FreeSocketMutex();

			log_info(
					"ConnectSocket: Operating system resources consumed by socket mutex freed.");

			CloseSocket(sockFd);

			/* If we are logging to a file and not the screen, print a message on the
			 * screen for an interactive user that the connect operation failed. */
			if (get_log_file_handle() != stdout) {
				fprintf(stdout, CONNECT_OPERATION_FAILED, hostnameOrIp, port);
			}

			close_log_file_handles();

			log_debug("ConnectSocket: Done.");

			exit(ERROR);
		}

		log_info("ConnectSocket: Connected to the server at '%s' on port %d.",
				hostnameOrIp, port);

		log_info("ConnectSocket: Releasing the socket mutex...");
	}
	UnlockSocketMutex();

	log_info("ConnectSocket: The socket mutex has been released.");

	log_info("ConnectSocket: result = %d", result);

	log_debug("ConnectSocket: Done.");

	return result;
}

void CloseSocket(int sockFd) {
	log_debug("In CloseSocket");

	log_debug("CloseSocket: sockFd = %d", sockFd);

	log_info("CloseSocket: Checking for a valid socket file descriptor...");

	if (!IsSocketValid(sockFd)) {
		log_error("CloseSocket: Valid socket file descriptor not passed.");

		return;	// just silently fail if the socket file descriptor passed is invalid
	}

	log_info("CloseSocket: A valid socket file descriptor was passed.");

	log_info(
			"CloseSocket: Attempting to shut down the socket with file descriptor %d...",
			sockFd);

	if (OK != shutdown(sockFd, SHUT_RD)) {
		/* This is not really an error, since shutting down a socket really just means disabling
		 * reads/writes on an open socket, not closing it.  Who cares if we cannot perform this
		 * operation? */

		log_warning(
				"CloseSocket: Failed to shut down the socket with file descriptor %d.",
				sockFd);
	} else {
		log_info("CloseSocket: Socket shut down successfully.");
	}

	log_info("CloseSocket: Attempting to close the socket...");

	int retval = close(sockFd);

	if (retval < 0) {
		log_error("CloseSocket: Failed to close the socket.");

		log_debug("CloseSocket: Done.");

		return;
	}

	log_info("CloseSocket: Socket closed successfully.");

	log_debug("CloseSocket: Done.");
}
